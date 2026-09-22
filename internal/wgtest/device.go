// Package wgtest wraps a userspace WireGuard device for netdiag's handshake
// tests.
//
// The device runs entirely in-process: a fake TUN (tuntest.ChannelTUN) over a
// real UDP bind, so it needs no TUN device, no kernel module, and no cgo -
// the Windows client builds with CGO_ENABLED=0. The server side is passive:
// it configures no client endpoint and never initiates; it learns the
// client's source address from the incoming handshake packets, which is
// exactly the NAT observation the report is built from. Only the client
// initiates, via a persistent keepalive: a keepalive sent with no handshake
// keypair is converted into a handshake initiation (see the wireguard
// device's SendStagedPackets), so the client arms the keepalive only after
// its endpoint is set. Having both sides initiate at once conflicts the
// index tables and the handshake never completes.
package wgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// Device is an in-memory WireGuard endpoint: a ChannelTUN behind a real UDP
// bind. Packets injected into TUN.Outbound are encrypted and sent to the
// configured peer; decrypted packets arrive on TUN.Inbound.
type Device struct {
	*device.Device
	TUN *tuntest.ChannelTUN
	IP  netip.Addr
	pk  [32]byte
}

// newKey returns a fresh random Curve25519 private key.
func newKey() [32]byte {
	var sk [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		panic(fmt.Sprintf("wgtest: read key: %v", err))
	}
	return sk
}

// publicKey derives the WireGuard public key from a private key.
func publicKey(sk [32]byte) [32]byte {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &sk)
	return pub
}

// DerivePublicKey is the exported form of publicKey. It lets a caller publish
// a device's public key before the device itself is constructed, which is the
// WireGuard-over-TLS handshake: the client sends its public key over the TLS
// stream first, so it must derive it from its private key without a device.
func DerivePublicKey(sk [32]byte) [32]byte { return publicKey(sk) }

// New builds an in-memory device at tunnel address ip, listening on
// listenPort (0 picks an ephemeral port, read back with ListenPort). If
// peerPub is non-zero the peer at peerIP is configured immediately; otherwise
// the device starts peerless (the server side, which adds clients on demand
// with AddPeer).
func New(ip netip.Addr, listenPort int, peerPub [32]byte, peerIP netip.Addr) (*Device, error) {
	return newDevice(ip, listenPort, peerPub, peerIP)
}

// NewClient builds the client side of a handshake test: an ephemeral-port
// device, pre-peered with the server (peerPub at peerIP). No keepalive is
// armed yet: the client points the peer at the server with
// SetEndpointAndKeepalive, which arms the keepalive and starts the handshake.
func NewClient(ip netip.Addr, peerPub [32]byte, peerIP netip.Addr) (*Device, error) {
	return newDevice(ip, 0, peerPub, peerIP)
}

// NewWithBind builds a device exactly like New, but behind a caller-supplied
// conn.Bind instead of the default UDP StdNetBind. The bind is passed straight
// to device.NewDevice, which is why the device is created in the "down" state
// here and only brought up by the caller once the bind is ready to receive.
// This is the entry point for transports that are not UDP, such as the
// WireGuard-over-TLS test that wraps a *tls.Conn in a custom bind.
func NewWithBind(ip netip.Addr, sk [32]byte, peerPub [32]byte, peerIP netip.Addr, bind conn.Bind) (*Device, error) {
	return newDeviceWithBind(ip, sk, peerPub, peerIP, bind, 0)
}

// NewClientWithBind builds the client side of a handshake test exactly like
// NewClient, but behind a caller-supplied conn.Bind instead of the default
// UDP StdNetBind. It generates a fresh random key internally, so it is the
// entry point for the WireGuard-over-TLS client, which must Up() its device
// only after its *tls.Conn is dialled and the control keys have been
// exchanged.
func NewClientWithBind(ip netip.Addr, peerPub [32]byte, peerIP netip.Addr, bind conn.Bind) (*Device, error) {
	return newDeviceWithBind(ip, newKey(), peerPub, peerIP, bind, 0)
}

// NewRandomKey returns a fresh random Curve25519 private key. It is exposed so
// the server side of a WireGuard-over-TLS handshake can generate its own
// device key per connection, mirroring the client's key generation.
func NewRandomKey() [32]byte {
	return newKey()
}

func newDevice(ip netip.Addr, listenPort int, peerPub [32]byte, peerIP netip.Addr) (*Device, error) {
	sk := newKey()
	d, err := newDeviceWithBind(ip, sk, peerPub, peerIP, conn.NewStdNetBind(), listenPort)
	if err != nil {
		return nil, err
	}
	// The UDP bind is already connected (it listens on the requested port) the
	// instant the device is constructed, so the device can be brought up
	// immediately - the existing handshake tests rely on New/NewClient returning
	// an up, ready device. Callers of NewWithBind that supply a non-UDP bind
	// (e.g. a TLS connection that is not yet connected) Up() the device
	// themselves once that bind is ready.
	if err := d.Up(); err != nil {
		d.Close()
		return nil, fmt.Errorf("wgtest: up: %w", err)
	}
	return d, nil
}

func newDeviceWithBind(ip netip.Addr, sk [32]byte, peerPub [32]byte, peerIP netip.Addr, bind conn.Bind, listenPort int) (*Device, error) {
	cfg := uapi(
		"private_key", hex.EncodeToString(sk[:]),
		"listen_port", strconv.Itoa(listenPort),
	)
	if peerPub != ([32]byte{}) {
		cfg += uapi(
			"replace_peers", "true",
			"public_key", hex.EncodeToString(peerPub[:]),
			"protocol_version", "1",
			"replace_allowed_ips", "true",
			"allowed_ip", peerIP.String()+"/32",
		)
	}
	chTun := tuntest.NewChannelTUN()
	d := &Device{
		Device: device.NewDevice(chTun.TUN(), bind,
			device.NewLogger(device.LogLevelVerbose, "")),
		TUN: chTun,
		IP:  ip,
		pk:  sk,
	}
	if err := d.IpcSet(cfg); err != nil {
		d.Close()
		return nil, fmt.Errorf("wgtest: configure: %w", err)
	}
	// The device is left in the down state here on purpose. For a UDP bind the
	// caller (newDevice) brings it up immediately, because the bind is already
	// listening the instant the device is constructed. A caller of
	// NewWithBind that supplies a custom bind - such as the WireGuard-over-TLS
	// transport, which is only connected once its *tls.Conn is dialled - Up()s
	// the device itself after that bind is ready to receive, so the device is
	// never up behind a bind that cannot yet serve packets.
	return d, nil
}

// PublicKey is the device's own WireGuard public key.
func (d *Device) PublicKey() [32]byte { return publicKey(d.pk) }

// ReplacePeer makes pub the device's only peer, allowing only allowedIP.
// The peer is not pointed at any endpoint: the device learns the peer's
// source address from the packets it receives (the passive server model).
// Replacing (rather than accumulating) keeps the diagnostic device single-
// client: a new client run supersedes the previous one instead of breaking
// Status, which reports on exactly one peer.
func (d *Device) ReplacePeer(pub [32]byte, allowedIP netip.Addr) error {
	return d.IpcSet(uapi(
		"replace_peers", "true",
		"public_key", hex.EncodeToString(pub[:]),
		"replace_allowed_ips", "true",
		"allowed_ip", allowedIP.String()+"/32",
	))
}

// SetEndpointAndKeepalive points the peer at endpoint and arms a persistent
// keepalive every secs seconds. Setting the interval from 0 triggers one
// immediate keepalive, and with no keypair yet that keepalive is sent as the
// handshake initiation - so this call is what starts the handshake and must
// come after NewClient (which deliberately leaves the interval at 0). The
// interval then keeps the NAT mapping warm and lets the client re-initiate
// after a rekey. The server must never call this.
func (d *Device) SetEndpointAndKeepalive(peerPub [32]byte, endpoint string, secs int) error {
	return d.IpcSet(uapi(
		"public_key", hex.EncodeToString(peerPub[:]),
		"endpoint", endpoint,
		"persistent_keepalive_interval", strconv.Itoa(secs),
	))
}

// Status is the device's view of its (single) peer: the observed source
// address, the last handshake time, and the byte counters.
type Status struct {
	Endpoint         string `json:"endpoint"`
	LastHandshakeSec uint64 `json:"last_handshake_time_sec"`
	TxBytes          uint64 `json:"tx_bytes"`
	RxBytes          uint64 `json:"rx_bytes"`
}

// Status snapshots the device via IpcGet. The diagnostic devices carry at
// most one peer; Status refuses to guess which peer's counters to report if
// more than one is configured.
func (d *Device) Status() (Status, error) {
	out, err := d.IpcGet()
	if err != nil {
		return Status{}, fmt.Errorf("wgtest: IpcGet: %w", err)
	}
	m := map[string]string{}
	peers := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		k, v, _ := strings.Cut(line, "=")
		if k == "public_key" {
			peers++
		}
		m[k] = v
	}
	if peers > 1 {
		return Status{}, fmt.Errorf("wgtest: %d peers configured, want at most 1", peers)
	}
	st := Status{Endpoint: m["endpoint"]}
	st.LastHandshakeSec, _ = strconv.ParseUint(m["last_handshake_time_sec"], 10, 64)
	st.TxBytes, _ = strconv.ParseUint(m["tx_bytes"], 10, 64)
	st.RxBytes, _ = strconv.ParseUint(m["rx_bytes"], 10, 64)
	return st, nil
}

// WaitHandshake blocks until the device reports a completed handshake, or ctx
// is done. It returns the time elapsed since the call.
func (d *Device) WaitHandshake(ctx context.Context) (time.Duration, error) {
	t0 := time.Now()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		st, err := d.Status()
		if err == nil && st.LastHandshakeSec > 0 {
			return time.Since(t0), nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

// ListenPort is the device's actual UDP port (a 0 request picks an ephemeral
// one, so it must be read back).
func (d *Device) ListenPort() (int, error) {
	out, err := d.IpcGet()
	if err != nil {
		return 0, fmt.Errorf("wgtest: IpcGet: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.Atoi(v)
			if err != nil {
				return 0, fmt.Errorf("wgtest: bad listen_port %q: %w", v, err)
			}
			return port, nil
		}
	}
	return 0, fmt.Errorf("wgtest: no listen_port in dump")
}

// Close shuts the device down and waits for its routines to finish.
func (d *Device) Close() {
	d.Device.Close()
	<-d.Device.Wait()
}

// uapi renders alternating key/value pairs as the "key=value" lines that
// IpcSet consumes.
func uapi(pairs ...string) string {
	var b strings.Builder
	for i, s := range pairs {
		if i%2 == 0 {
			b.WriteString(s)
			b.WriteByte('=')
		} else {
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
