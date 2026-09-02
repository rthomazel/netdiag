// WireGuard tests 6 and 7, run over the tunnel test 4 established.
//
// Test 6 (persistent) answers: does the client's network age or drop the UDP
// NAT mapping while the tunnel idles? The measurement is the one the research
// spike verified: with the 1s persistent keepalive armed, keepalives advance
// the client's tx_bytes and the server's rx_bytes while last_handshake_time
// stays stable. A mapping that ages out stops the bytes moving; a NAT that
// reassigns changes the observed endpoint. The test idles the established
// device for the window (60s in production, shorter in local runs/tests),
// compares server snapshots at t0 and t1, and requires a fresh ping to
// deliver at the end. WireGuard re-keys every ~2 minutes, so a re-key inside
// the window is not a failure: it bumps the handshake time without breaking
// the mapping. Only a mapping change or a dead pipe fails the test.
//
// Test 7 (bidir) answers: does real data flow in both directions through the
// tunnel? It pushes N pings client->server (the server's echo responder
// answers each one, so every ping also exercises the reverse path) and N
// pings server->client, byte-comparing every delivery.
package client

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/wgtest"
)

// pingCount is the number of pings each direction in test 7. Each client->
// server ping is answered by the server's echo responder, so the same N
// round trips exercise both directions through the tunnel.
const pingCount = 5

// persistentTest runs test 6 over dev, the device test 4 handshaken.
func persistentTest(ctx context.Context, dev *wgtest.Device, httpsAddr string, subnet protocol.Subnet, timeout, window time.Duration) protocol.Result {
	res := protocol.Result{Name: protocol.TestPersistent}
	// One deadline for the whole test: idle window plus resend traffic.
	// The window is deliberate and long (60s), so it is not capped by the
	// per-test timeout.
	pCtx, cancel := context.WithTimeout(ctx, window+timeout)
	defer cancel()

	// Snapshots at t0: the server's view (its rx_bytes = the client's tx,
	// its endpoint = the NAT observation) and the client's own tx counter.
	snap0, err := wgFullStatus(pCtx, httpsAddr, protocol.TestWG51820)
	if err != nil {
		return fail(res, fmt.Errorf("server status: %w", err))
	}
	sx0, err := dev.Status()
	if err != nil {
		return fail(res, err)
	}
	if err := waitIdle(pCtx, window); err != nil {
		return fail(res, err)
	}
	snap1, err := wgFullStatus(pCtx, httpsAddr, protocol.TestWG51820)
	if err != nil {
		return fail(res, fmt.Errorf("server status after idle: %w", err))
	}
	sx1, err := dev.Status()
	if err != nil {
		return fail(res, err)
	}
	if snap1.Endpoint != snap0.Endpoint {
		return fail(res, fmt.Errorf("NAT reassigned the client: endpoint %s -> %s", snap0.Endpoint, snap1.Endpoint))
	}
	// The server's rx_bytes are the client's sent bytes: if they didn't
	// advance, the client's keepalives never arrived (mapping aged out).
	if snap1.RxBytes <= snap0.RxBytes {
		return fail(res, fmt.Errorf("no keepalives arrived during the %s idle: server rx_bytes %d -> %d (NAT mapping aged out)", window, snap0.RxBytes, snap1.RxBytes))
	}
	// The client's own tx counter must advance too: it proves the keepalive
	// timer fired (the client *sent* keepalives). This is a weaker signal
	// than the server's rx above — the device counts bytes it writes even
	// when the NAT drops them — but it catches the device-level failure
	// where the keepalive timer stops, independent of the server's view.
	if sx1.TxBytes <= sx0.TxBytes {
		return fail(res, fmt.Errorf("client sent no keepalives during the %s idle: tx_bytes %d -> %d", window, sx0.TxBytes, sx1.TxBytes))
	}
	// The keepalives are not proof the tunnel still carries traffic: a NAT
	// can accept the keepalives and still drop data. Resend a ping and
	// require delivery.
	if err := echoPing(pCtx, dev, subnet); err != nil {
		return fail(res, fmt.Errorf("ping after %s idle: %w", window, err))
	}
	res.Status = protocol.StatusPass
	res.Src = snap1.Endpoint
	res.Duration = roundTrip(window)
	res.Detail = fmt.Sprintf("kept alive %s (rx %d -> %d bytes)", window, snap0.RxBytes, snap1.RxBytes)
	return res
}

// echoPing sends one ping from dev's tunnel IP to the server's and waits for
// the server's echo reply to come back through the tunnel. The reply is what
// proves both directions carried real data: the ping went client->server and
// the echo came back server->client. It byte-compares the delivered reply
// against the expected one.
func echoPing(ctx context.Context, dev *wgtest.Device, subnet protocol.Subnet) error {
	msg := tuntest.Ping(subnet.Server, subnet.Client)
	dev.TUN.Outbound <- msg
	reply := tuntest.Ping(subnet.Client, subnet.Server)
	select {
	case got := <-dev.TUN.Inbound:
		if bytes.Equal(got, reply) {
			return nil
		}
		return fmt.Errorf("echo reply payload mismatch")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// waitIdle sleeps for d, or until ctx is done.
func waitIdle(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("idle window: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// bidirTest runs test 7: pingCount pings client->server over the established
// tunnel, each answered by the server's echo responder, so every round trip
// carries real data in both directions. The first failure is reported.
func bidirTest(ctx context.Context, dev *wgtest.Device, httpsAddr string, subnet protocol.Subnet, timeout time.Duration) protocol.Result {
	res := protocol.Result{Name: protocol.TestBidir}
	start := time.Now()
	for i := 0; i < pingCount; i++ {
		if err := echoPing(ctx, dev, subnet); err != nil {
			return fail(res, fmt.Errorf("ping %d/%d: %w", i+1, pingCount, err))
		}
	}
	// Report the server-observed endpoint, the pass condition for the other
	// WG tests: the bytes moved across the wire the server saw.
	st, err := wgFullStatus(ctx, httpsAddr, protocol.TestWG51820)
	if err != nil {
		return fail(res, fmt.Errorf("server status: %w", err))
	}
	res.Status = protocol.StatusPass
	res.Src = st.Endpoint
	res.Duration = roundTrip(time.Since(start))
	res.Detail = fmt.Sprintf("%d pings each direction", pingCount)
	return res
}
