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
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/wgtest"
)

// WG owns the two WireGuard diagnostic devices, keyed by test name.
type WG struct {
	devs map[string]*wgtest.Device
}

// NewWG builds the two passive WireGuard devices that serve tests 4 and 5.
// Each listens on the port parsed from the given address (0 picks an
// ephemeral port, for local runs); the client keys are unknown at this
// point - clients register with Register.
func NewWG(addr51820, addr443 string) (*WG, error) {
	p51820, err := portOfAddr(addr51820)
	if err != nil {
		return nil, err
	}
	p443, err := portOfAddr(addr443)
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
	return &WG{devs: map[string]*wgtest.Device{
		protocol.TestWG51820: dev51820,
		protocol.TestWG443:   dev443,
	}}, nil
}

// Keys returns the public keys of both devices (hex-encoded), in the shape
// the /wg handler serves.
func (w *WG) Keys() protocol.WGKeys {
	pub51820 := w.devs[protocol.TestWG51820].PublicKey()
	pub443 := w.devs[protocol.TestWG443].PublicKey()
	return protocol.WGKeys{
		WG51820: hex.EncodeToString(pub51820[:]),
		WG443:   hex.EncodeToString(pub443[:]),
	}
}

// Register makes the client identified by pub the named test's current
// diagnostic peer: a passive peer allowed to address the client's tunnel IP
// only. It replaces the previously registered peer, so repeated (or
// concurrent) client runs each start clean instead of accumulating peers.
func (w *WG) Register(name string, pub [32]byte) error {
	dev, subnet, ok := w.forTest(name)
	if !ok {
		return fmt.Errorf("unknown wg test %q", name)
	}
	return dev.ReplacePeer(pub, subnet.Client)
}

// Port returns the device's actual UDP listen port (it must be read back,
// since a 0 request picks an ephemeral one).
func (w *WG) Port(name string) (int, error) {
	dev, _, ok := w.forTest(name)
	if !ok {
		return 0, fmt.Errorf("unknown wg test %q", name)
	}
	return dev.ListenPort()
}

// Status snapshots the named test's device: the observed client endpoint
// (empty until the client's first handshake packet arrives) plus the
// handshake time and byte counters.
func (w *WG) Status(name string) (wgtest.Status, error) {
	dev, _, ok := w.forTest(name)
	if !ok {
		return wgtest.Status{}, fmt.Errorf("unknown wg test %q", name)
	}
	return dev.Status()
}

// Close shuts both devices down and waits for their routines to finish.
func (w *WG) Close() {
	for _, dev := range w.devs {
		dev.Close()
	}
}

// Known reports whether name is one of the WireGuard test names.
func (w *WG) Known(name string) bool {
	_, _, ok := w.forTest(name)
	return ok
}

// forTest resolves a test name to its device and the client's tunnel address.
func (w *WG) forTest(name string) (*wgtest.Device, protocol.Subnet, bool) {
	var subnet protocol.Subnet
	switch name {
	case protocol.TestWG51820:
		subnet = protocol.WGSubnet51820
	case protocol.TestWG443:
		subnet = protocol.WGSubnet443
	default:
		return nil, protocol.Subnet{}, false
	}
	dev, ok := w.devs[name]
	if !ok {
		return nil, protocol.Subnet{}, false
	}
	return dev, subnet, true
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
