// WG holds the two passive WireGuard devices that serve tests 4 and 5.
//
// Each device listens on its test port, generates its own keypair at startup,
// and configures no client endpoint: when a client's handshake packets
// arrive, the device learns the client's source address from them. That
// observed endpoint is exactly the NAT info the report is built from.
// Clients announce themselves via Register (called from the /wg/register
// handler); Keys hands out the public keys over the control plane so the
// client needs no pre-shared material.
package server

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/wgtest"
	"github.com/rthomazel/netdiag/internal/wgtun"
)

// WG owns the two WireGuard diagnostic devices, keyed by test name.
type WG struct {
	devs map[string]*dev
	done chan struct{}

	// overTLS holds the device serving the current WireGuard-over-TLS
	// handshake (test 9). There is one device per marker-SNI TLS connection;
	// the latest connection wins, since the client polls this single status
	// slot. The mutex guards the pointer only - the device itself is owned by
	// the handler that created it.
	overTLSMu sync.Mutex
	overTLS   *wgtest.Device
}

// NewWG builds the three passive WireGuard devices that serve tests 4, 5,
// and 6. Each listens on the port parsed from the given address (0 picks an
// ephemeral port, for local runs); the client keys are unknown at this
// point - clients register with Register.
func NewWG(addr51820, addr443, addrArbitrary string) (*WG, error) {
	p51820, err := portOfAddr(addr51820)
	if err != nil {
		return nil, err
	}
	p443, err := portOfAddr(addr443)
	if err != nil {
		return nil, err
	}
	pArb, err := portOfAddr(addrArbitrary)
	if err != nil {
		return nil, err
	}
	dev51820, err := wgtest.New(protocol.WGSubnet51820.Server, p51820, [32]byte{}, netip.Addr{})
	if err != nil {
		return nil, fmt.Errorf("wg %s: %w", protocol.TestWG51820, err)
	}
	dev443, err := wgtest.New(protocol.WGSubnet443.Server, p443, [32]byte{}, netip.Addr{})
	if err != nil {
		dev51820.Close()
		return nil, fmt.Errorf("wg %s: %w", protocol.TestWG443, err)
	}
	devArb, err := wgtest.New(protocol.WGSubnetArbitrary.Server, pArb, [32]byte{}, netip.Addr{})
	if err != nil {
		dev51820.Close()
		dev443.Close()
		return nil, fmt.Errorf("wg %s: %w", protocol.TestWGAbitrary, err)
	}
	w := &WG{
		devs: map[string]*dev{
			protocol.TestWG51820: {name: protocol.TestWG51820, dev: dev51820, subnet: protocol.WGSubnet51820},
			protocol.TestWG443:   {name: protocol.TestWG443, dev: dev443, subnet: protocol.WGSubnet443},
			protocol.TestWGAbitrary: {name: protocol.TestWGAbitrary, dev: devArb, subnet: protocol.WGSubnetArbitrary},
		},
		done: make(chan struct{}),
	}
	for _, d := range w.devs {
		go w.echoLoop(d)
	}
	return w, nil
}

// Keys returns the public keys of all three devices (hex-encoded), in the
// shape the /wg handler serves.
func (w *WG) Keys() protocol.WGKeys {
	pub51820 := w.devs[protocol.TestWG51820].dev.PublicKey()
	pub443 := w.devs[protocol.TestWG443].dev.PublicKey()
	pubArb := w.devs[protocol.TestWGAbitrary].dev.PublicKey()
	return protocol.WGKeys{
		WG51820:    hex.EncodeToString(pub51820[:]),
		WG443:      hex.EncodeToString(pub443[:]),
		WGAbitrary: hex.EncodeToString(pubArb[:]),
	}
}

// Register makes the client identified by pub the named test's current
// diagnostic peer: a passive peer allowed to address the client's tunnel IP
// only. It replaces the previously registered peer, so repeated (or
// concurrent) client runs each start clean instead of accumulating peers.
func (w *WG) Register(name string, pub [32]byte) error {
	d, ok := w.forTest(name)
	if !ok {
		return fmt.Errorf("unknown wg test %q", name)
	}
	return d.dev.ReplacePeer(pub, d.subnet.Client)
}

// Port returns the device's actual UDP listen port (it must be read back,
// since a 0 request picks an ephemeral one).
func (w *WG) Port(name string) (int, error) {
	d, ok := w.forTest(name)
	if !ok {
		return 0, fmt.Errorf("unknown wg test %q", name)
	}
	return d.dev.ListenPort()
}

// Status snapshots the named test's device: the observed client endpoint
// (empty until the client's first handshake packet arrives) plus the
// handshake time and byte counters.
func (w *WG) Status(name string) (wgtest.Status, error) {
	d, ok := w.forTest(name)
	if !ok {
		return wgtest.Status{}, fmt.Errorf("unknown wg test %q", name)
	}
	return d.dev.Status()
}

// handleWGOverTLS serves one WireGuard-over-TLS handshake (test 9). The
// client and server exchange device public keys as control frames, then run
// the handshake over the same TLS connection. The client initiates via its
// keepalive; the server device is passive and replies.
//
// The device created here is tracked in the WG slot so the client can poll its
// status over HTTPS after the handshake completes. The device is held active
// until the client closes the connection, because the client polls the status
// only after the handshake finishes - and it closes the connection when its
// test returns.
func handleWGOverTLS(ctx context.Context, conn *tls.Conn, wg *WG) {
	log.Printf("%s from %s", protocol.TestWGOverTLS, conn.RemoteAddr())

	// Read the client's public key. The client writes first, so the server
	// reads first: this ordering is deadlock-free.
	typ, data, err := protocol.ReadFrame(conn)
	if err != nil {
		log.Printf("%s: read client key: %v", protocol.TestWGOverTLS, err)
		return
	}
	if typ != protocol.WgOverTLSControlType || len(data) != 32 {
		log.Printf("%s: bad client key frame", protocol.TestWGOverTLS)
		return
	}
	var clientPub [32]byte
	copy(clientPub[:], data)

	// Create a passive device for this connection. The client generates its
	// own key; the server generates a fresh one here, mirroring the client.
	sk := wgtest.NewRandomKey()
	bind := wgtest.NewTLSBind(conn)
	dev, err := wgtest.NewWithBind(protocol.WGSubnetTLS.Server, sk, clientPub, protocol.WGSubnetTLS.Client, bind)
	if err != nil {
		log.Printf("%s: create device: %v", protocol.TestWGOverTLS, err)
		return
	}
	defer dev.Close()

	if err := dev.Up(); err != nil {
		log.Printf("%s: up device: %v", protocol.TestWGOverTLS, err)
		return
	}
	wg.setOverTLS(dev)
	defer wg.clearOverTLS()

	// Send our public key back. The client reads this after it has written its
	// own, so the exchange is a clean request-response.
	serverPub := dev.PublicKey()
	if err := protocol.WriteFrame(conn, protocol.WgOverTLSControlType, serverPub[:]); err != nil {
		log.Printf("%s: write server key: %v", protocol.TestWGOverTLS, err)
		return
	}

	// Wait for the handshake to complete, holding the device active until the
	// client closes the connection so it can poll the status afterward.
	hsDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				st, err := dev.Status()
				if err == nil && st.LastHandshakeSec > 0 {
					close(hsDone)
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	<-hsDone
	<-bind.ReaderExited()
}

// setOverTLS records the device serving the current WireGuard-over-TLS
// handshake. The latest connection wins, so a stale peer slot never outlives
// its connection.
func (w *WG) setOverTLS(dev *wgtest.Device) {
	w.overTLSMu.Lock()
	w.overTLS = dev
	w.overTLSMu.Unlock()
}

// clearOverTLS drops the active over-TLS device slot. It is called after the
// handshake connection closes so a subsequent status poll does not report on
// a dead peer.
func (w *WG) clearOverTLS() {
	w.overTLSMu.Lock()
	w.overTLS = nil
	w.overTLSMu.Unlock()
}

// statusOverTLS snapshots the current over-TLS handshake device. It returns an
// empty status (not an error) when no connection is active yet, so the client
// can poll the slot over HTTPS without special-casing a 404.
func (w *WG) statusOverTLS() (wgtest.Status, error) {
	w.overTLSMu.Lock()
	dev := w.overTLS
	w.overTLSMu.Unlock()
	if dev == nil {
		return wgtest.Status{}, nil
	}
	return dev.Status()
}

// echoLoop is the tunnel echo responder (tests 6 and 7): it reads ping
// packets arriving on the device's fake TUN and writes a reply back into the
// device's own outbound channel — from the server's tunnel IP to the
// client's. It responds only to pings it receives; the server stays passive
// and never initiates tunnel traffic.
func (w *WG) echoLoop(d *dev) {
	for {
		select {
		case in := <-d.dev.TUN.Inbound:
			if _, ok := wgtun.PingSrc(in); !ok {
				continue
			}
			// Reply from the server's own tunnel IP to the client's: the
			// destination is the client's tunnel IP (d.subnet.Client) and the
			// source is the server's (d.subnet.Server). The client byte-
			// compares against exactly this, so the source must be the server,
			// not an echo of the received packet's source. The send is selected
			// against w.done so a shutdown cannot leave this loop blocked on an
			// Outbound send whose consumer (the device's TUN read loop) has
			// already stopped.
			out := d.dev.TUN.Outbound
			select {
			case out <- tuntest.Ping(d.subnet.Client, d.subnet.Server):
			case <-w.done:
				return
			}
		case <-w.done:
			return
		}
	}
}

// Close shuts both devices down and waits for their routines to finish.
func (w *WG) Close() {
	close(w.done)
	for _, d := range w.devs {
		d.dev.Close()
	}
}

// Known reports whether name is one of the WireGuard test names.
func (w *WG) Known(name string) bool {
	_, ok := w.forTest(name)
	return ok
}

// dev pairs a WireGuard device with its test name and tunnel subnet.
type dev struct {
	name   string
	dev    *wgtest.Device
	subnet protocol.Subnet
}

// forTest resolves a test name to its device entry.
func (w *WG) forTest(name string) (*dev, bool) {
	d, ok := w.devs[name]
	return d, ok
}

// portOfAddr extracts the port from a "host:port" listen address.
func portOfAddr(addr string) (int, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("bad wg address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return 0, fmt.Errorf("bad wg port in %q: %v", addr, err)
	}
	return port, nil
}
