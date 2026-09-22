// WireGuard-over-TLS handshake test (9).
//
// Test 9 answers a different question than the UDP handshake tests 4-7: can a
// WireGuard handshake survive inside an ordinary TLS connection over TCP/443,
// the way production WireGuard traffic might blend in with HTTPS? The client
// dials the HTTPS port again, but this time with a distinctive marker SNI so
// the server routes the connection to a passive WireGuard device instead of
// the HTTPS control plane.
//
// The client and server exchange their device public keys over the TLS stream
// as control frames, then run the handshake over the same connection behind a
// tlsConn-backed conn.Bind. Only the client initiates: it arms a persistent
// keepalive, and a keepalive sent with no handshake keypair is converted into
// the handshake initiation (see the wireguard device's SendStagedPackets). The
// server's device is passive and replies.
//
// Success is judged entirely on the server's view: it must have observed the
// client's source address AND confirmed the handshake. That is the NAT
// information the report is built from, and it is exactly what the UDP
// handshake tests report too.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/wgtest"
)

// wgOverTLSTest runs test 9: a WireGuard handshake carried inside a TLS
// connection over the HTTPS port. addr is the HTTPS endpoint the client dials
// with the marker SNI; httpsAddr is the control plane the client polls for the
// server's view of the handshake.
func wgOverTLSTest(ctx context.Context, addr, httpsAddr string, timeout, reqTimeout time.Duration) protocol.Result {
	res := protocol.Result{Name: protocol.TestWGOverTLS}

	// Dial the shared HTTPS port with the marker SNI. InsecureSkipVerify: the
	// test measures reachability of the transport, not the certificate.
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialTLSOverTLS(dialCtx, addr)
	if err != nil {
		return fail(res, fmt.Errorf("tls dial: %w", err))
	}
	defer conn.Close()

	// Exchange device public keys over the TLS stream. The client goes first
	// (its key lets the server create a passive peer), and the server replies
	// with its own. This ordering is deadlock-free: the client writes then
	// reads, the server reads then writes.
	clientSk := wgtest.NewRandomKey()
	clientPub := wgtest.DerivePublicKey(clientSk)
	if err := protocol.WriteFrame(conn, protocol.WgOverTLSControlType, clientPub[:]); err != nil {
		return fail(res, fmt.Errorf("send client key: %w", err))
	}
	serverPub, err := readServerPub(conn)
	if err != nil {
		return fail(res, fmt.Errorf("read server key: %w", err))
	}

	// Bridge the WireGuard device to this TLS connection. The device is left
	// DOWN until Up() is called, because the bind is only connected once the
	// *tls.Conn is dialled.
	bind := wgtest.NewTLSBind(conn)
	dev, err := wgtest.NewWithBind(protocol.WGSubnetTLS.Client, clientSk, serverPub, protocol.WGSubnetTLS.Server, bind)
	if err != nil {
		return fail(res, fmt.Errorf("create device: %w", err))
	}
	defer dev.Close()

	if err := dev.Up(); err != nil {
		return fail(res, fmt.Errorf("up device: %w", err))
	}

	// Point the peer at the server and arm the keepalive that triggers the
	// handshake initiation.
	if err := dev.SetEndpointAndKeepalive(serverPub, addr, 1); err != nil {
		return fail(res, fmt.Errorf("set endpoint: %w", err))
	}

	// The handshake completes on the client when it receives the server's
	// response.
	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	hsDur, err := dev.WaitHandshake(hsCtx)
	if err != nil {
		return fail(res, fmt.Errorf("handshake: %w", err))
	}

	// The real proof is on the server: it must have observed the client's
	// source address and confirmed the handshake.
	st, err := wgFetchStatus(ctx, httpsAddr, protocol.TestWGOverTLS, reqTimeout)
	if err != nil {
		return fail(res, fmt.Errorf("server status: %w", err))
	}
	if st.Endpoint == "" {
		return fail(res, fmt.Errorf("server confirmed the handshake but observed no client source"))
	}

	res.Status = protocol.StatusPass
	res.Src = st.Endpoint
	res.Duration = roundTrip(hsDur)
	res.Detail = "handshake over TLS " + roundTrip(hsDur)
	return res
}

// dialTLSOverTLS dials addr as a TLS connection using the marker SNI so the
// server routes it to the WireGuard-over-TLS handler rather than the HTTPS
// control plane.
func dialTLSOverTLS(ctx context.Context, addr string) (*tls.Conn, error) {
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         protocol.MarkerSNI,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// readServerPub reads the public key the server writes back in its control
// frame, once it has recorded the client's key.
func readServerPub(conn *tls.Conn) ([32]byte, error) {
	typ, data, err := protocol.ReadFrame(conn)
	if err != nil {
		return [32]byte{}, err
	}
	if typ != protocol.WgOverTLSControlType || len(data) != 32 {
		return [32]byte{}, fmt.Errorf("bad server key frame")
	}
	var pub [32]byte
	copy(pub[:], data)
	return pub, nil
}
