// WireGuard handshake tests (4: UDP/51820, 5: UDP/443).
//
// The client runs an in-memory WireGuard device (fake TUN over a real UDP
// bind, no TUN device, no kernel, no cgo). It fetches the server's public
// keys from the HTTPS control plane, registers its own device key, and starts
// the handshake by pointing the peer at the server and arming a 1s
// persistent keepalive - the keepalive with no keypair is what triggers the
// initiation. The handshake result comes from the server: it polls its own
// status endpoint until the handshake is confirmed there, and the source
// address the server observed the packets from is what the report shows.
// The server's WG device is passive: it never initiates and learns the
// client's endpoint from the arriving packets.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/wgtest"
)

// wgStatus is the server's view of a handshake device; the subset the
// client needs: the observed client endpoint and the handshake time.
type wgStatus struct {
	Endpoint         string `json:"endpoint"`
	LastHandshakeSec uint64 `json:"last_handshake_time_sec"`
	TxBytes          uint64 `json:"tx_bytes"`
	RxBytes          uint64 `json:"rx_bytes"`
}

// wgFetchKeys fetches the server's WireGuard public keys (hex) from the
// HTTPS control plane.
func wgFetchKeys(ctx context.Context, httpsAddr string, timeout time.Duration) (protocol.WGKeys, error) {
	var keys protocol.WGKeys
	if err := httpsGetJSON(ctx, "https://"+httpsAddr+"/wg", timeout, &keys); err != nil {
		return keys, err
	}
	if len(keys.WG51820) != 64 || len(keys.WG443) != 64 {
		return keys, fmt.Errorf("server returned malformed wg keys")
	}
	return keys, nil
}

func httpsGetJSON(ctx context.Context, url string, timeout time.Duration, out any) error {
	// InsecureSkipVerify: the test measures reachability, not the certificate.
	cli := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// wgTest runs one WireGuard handshake test against the named server device
// (protocol.TestWG51820 or protocol.TestWG443). addr is the WireGuard UDP
// endpoint the client dials; control (register/status) goes over httpsAddr.
//
// retain controls who closes the device afterwards: when non-nil the caller
// receives the handshaken device on success (test 6 reuses test 4's
// established mapping instead of building a third device) and must Close it;
// when nil the device is closed here.
func wgTest(ctx context.Context, name, addr, httpsAddr, peerPubHex string, subnet protocol.Subnet, timeout, reqTimeout time.Duration, retain **wgtest.Device) protocol.Result {
	res := protocol.Result{Name: name}
	peerPub, err := hex.DecodeString(peerPubHex)
	if err != nil || len(peerPub) != 32 {
		return fail(res, fmt.Errorf("bad server public key: %v", err))
	}
	dev, err := wgtest.NewClient(subnet.Client, [32]byte(peerPub), subnet.Server)
	if err != nil {
		return fail(res, err)
	}
	// The device is closed here on every path except the retained success
	// case (the caller takes ownership of dev and closes it). A closure that
	// is armed until the success path hands dev off keeps the failure paths
	// from leaking the device and its routines.
	owned := true
	defer func() {
		if owned {
			dev.Close()
		}
	}()
	pub := dev.PublicKey()
	if err := wgRegister(ctx, httpsAddr, name, hex.EncodeToString(pub[:]), timeout); err != nil {
		return fail(res, fmt.Errorf("register: %w", err))
	}
	// Point the peer at the server and arm the keepalive that triggers the
	// handshake initiation.
	if err := dev.SetEndpointAndKeepalive([32]byte(peerPub), addr, 1); err != nil {
		return fail(res, err)
	}
	// One deadline for the whole flow: the handshake and the server-side
	// confirmation share it, so a slow network can't stack two timeouts.
	rsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hsDur, err := dev.WaitHandshake(rsCtx)
	if err != nil {
		return fail(res, fmt.Errorf("handshake: %w", err))
	}
	st, err := wgFetchStatus(rsCtx, httpsAddr, name, reqTimeout)
	if err != nil {
		return fail(res, fmt.Errorf("server status: %w", err))
	}
	if st.Endpoint == "" {
		return fail(res, fmt.Errorf("server confirmed the handshake but observed no client source"))
	}
	if retain != nil {
		*retain = dev
		owned = false // caller now owns the device
	}
	res.Status = protocol.StatusPass
	res.Src = st.Endpoint
	res.Duration = roundTrip(hsDur)
	res.Detail = "handshake " + roundTrip(hsDur)
	return res
}

// wgRegister POSTs the client device's public key to the server so it adds a
// passive peer for it.
func wgRegister(ctx context.Context, httpsAddr, name, pubHex string, timeout time.Duration) error {
	body, _ := json.Marshal(map[string]string{"test": name, "public_key": pubHex})
	cli := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+httpsAddr+"/wg/register",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("register status %d", resp.StatusCode)
	}
	return nil
}

// wgFullStatus takes a single snapshot of the server's view of the named
// device. Test 6 compares two of these across the idle window; no polling,
// no confirmation — it just reads what the server has right now.
func wgFullStatus(ctx context.Context, httpsAddr, name string) (wgStatus, error) {
	var st wgStatus
	err := httpsGetJSON(ctx, "https://"+httpsAddr+"/wg/status/"+name, 5*time.Second, &st)
	return st, err
}

// wgFetchStatus polls the server's view of the named device until it shows a
// completed handshake AND the observed client source. Both are required: the
// server records the endpoint from the client's first handshake packet, before
// the handshake completes, so an endpoint alone is not proof the exchange
// finished. ctx bounds the whole poll; each request gets a short timeout so
// one slow status read cannot eat the remaining budget.
func wgFetchStatus(ctx context.Context, httpsAddr, name string, reqTimeout time.Duration) (wgStatus, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var st wgStatus
	var lastErr error
	for {
		lastErr = httpsGetJSON(ctx, "https://"+httpsAddr+"/wg/status/"+name, reqTimeout, &st)
		if lastErr == nil && st.LastHandshakeSec > 0 && st.Endpoint != "" {
			return st, nil
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return st, lastErr
			}
			if st.Endpoint == "" {
				return st, fmt.Errorf("server never observed a client endpoint")
			}
			return st, fmt.Errorf("server never confirmed the handshake")
		case <-ticker.C:
		}
	}
}
