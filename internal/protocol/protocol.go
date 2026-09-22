// Package protocol defines the wire format shared by the netdiag client and server.
//
// Two things live here:
//
//   - Result: the JSON the control plane returns for each named test, carrying the
//     source IP:port the server observed. This is the NAT-observation channel.
//   - The UDP-ACK wire format used by the generic-UDP test: a small binary request
//     the client sends and an application-level acknowledgment the server replies
//     with, so the client can tell real bidirectional UDP from one-way drops.
package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// Magic bytes identify the two directions of the UDP-ACK exchange.
const (
	MagicReq  byte = 0xA1 // client -> server
	MagicResp byte = 0xA2 // server -> client
)

// Fixed sizes of the two UDP-ACK frames.
const (
	ReqSize  = 12
	RespSize = 30
)

// Status values for a test result.
const (
	StatusPass = "pass"
	StatusFail = "fail"
)

// DefaultPersistentWindow is how long test 6 idles the established tunnel
// before resending traffic: the deliberate length of the diagnostic (a 60s
// window must survive to hold a NAT mapping), set at the default-60s
// production value. Local runs and tests pass a shorter window through the
// client's persistentWindow parameter.
const DefaultPersistentWindow = 60 * time.Second

// Test names. The client requests these by name; the server records a Result for
// each and the client fetches them back. Keeping the names in one place means the
// control plane path and the report line both use the same identifier.
const (
	TestHTTPS443   = "https443"
	TestTCP8443    = "tcp8443"
	TestUDP        = "udp"
	TestWG51820    = "wg51820"
	TestWG443      = "wg443"
	TestWGAbitrary = "wgarbitrary"
	TestPersistent = "persistent"
	TestBidir      = "bidir"
	// TestWGOverTLS is the WireGuard-over-TLS handshake test. The client dials
	// the HTTPS port again but with a distinctive-but-HTTPS-shaped SNI so the
	// server can route the connection to a passive WireGuard device instead of
	// the HTTPS control plane. The marker SNI stays visible in the plaintext
	// ClientHello on purpose: this test only probes whether the WireGuard
	// packet signature is hidden inside TLS, not whether the SNI itself is.
	TestWGOverTLS = "wgovertls"

	// MarkerSNI is the shared hostname the client sends in the TLS ClientHello
	// to select the WireGuard-over-TLS transport. It is shaped like an ordinary
	// HTTPS service name (a diagnostics subdomain on a German-style domain,
	// since the VPS lives in Germany) but is otherwise distinctive so it can
	// be routed on. The client and server must agree on this exact value.
	MarkerSNI = "en.zalando.de"
)

// WGKeys carries the server's WireGuard public keys (hex-encoded) for the
// handshake tests, fetched over the HTTPS control plane so the client needs
// no pre-shared keys.
type WGKeys struct {
	WG51820    string `json:"wg51820"`
	WG443      string `json:"wg443"`
	WGAbitrary string `json:"wgarbitrary"` // WireGuard handshake on an arbitrary (non-standard) UDP port
	WGOverTLS  string `json:"wgovertls"`   // WireGuard handshake encapsulated inside TLS/443
}

// Subnet is the tunnel address pair for one WireGuard test: the server's
// address and the client's. Each test gets its own private pair so the
// fake tunnels stay isolated and only carry diagnostic traffic.
type Subnet struct {
	Server netip.Addr
	Client netip.Addr
}

// Tunnel subnets for the WireGuard tests.
var (
	WGSubnet51820 = Subnet{Server: netip.MustParseAddr("10.66.0.1"), Client: netip.MustParseAddr("10.66.0.2")}
	WGSubnet443   = Subnet{Server: netip.MustParseAddr("10.67.0.1"), Client: netip.MustParseAddr("10.67.0.2")}
	// WGSubnetArbitrary is the tunnel pair for the arbitrary-port handshake
	// test. A third, independent subnet keeps the three devices isolated so a
	// handshake on one port never leaks onto another.
	WGSubnetArbitrary = Subnet{Server: netip.MustParseAddr("10.68.0.1"), Client: netip.MustParseAddr("10.68.0.2")}
	// WGSubnetTLS is the tunnel pair for the WireGuard-over-TLS handshake
	// test. A fourth, independent subnet keeps all four devices isolated so a
	// handshake on one transport never leaks onto another.
	WGSubnetTLS = Subnet{Server: netip.MustParseAddr("10.69.0.1"), Client: netip.MustParseAddr("10.69.0.2")}
)

// WgOverTLS frames carry a 4-byte big-endian length prefix followed by a
// body. The body's first byte is the frame type (WgOverTLSPacketType or
// WgOverTLSControlType); the remainder is the payload. WireGuard transport
// messages fit in the payload, so it is capped at WgOverTLSMaxData and the
// whole frame at WgOverTLSMaxFrame. These bounds stop a corrupt or hostile
// length prefix from driving an unbounded read.
const (
	// WgOverTLSHeaderLen is the size of the big-endian length prefix on every
	// frame.
	WgOverTLSHeaderLen = 4
	// WgOverTLSMaxData is the largest payload (the bytes after the frame's one
	// byte type) a frame may carry. It must accommodate a full WireGuard
	// transport message, whose size is bounded by the device's segment size
	// (up to 65535 on the default UDP path), so the 4-byte length prefix that
	// precedes it never has to describe a packet too large to read.
	WgOverTLSMaxData = 1 << 16
	// WgOverTLSMaxBody is the largest body (the type byte plus the payload).
	WgOverTLSMaxBody = 1 + WgOverTLSMaxData
	// WgOverTLSMaxFrame is the largest total frame size on the wire.
	WgOverTLSMaxFrame = WgOverTLSHeaderLen + WgOverTLSMaxBody
)

// Frame types carried in the leading byte of each WgOverTLS body.
const (
	WgOverTLSPacketType  byte = 1 // a raw WireGuard packet
	WgOverTLSControlType byte = 2 // a control message carrying a 32-byte key
)

// WriteFrame writes one framed message to w: a big-endian length of the body,
// the body's type byte, then the body's data.
func WriteFrame(w io.Writer, typ byte, data []byte) error {
	if len(data) > WgOverTLSMaxData {
		return fmt.Errorf("wgovertls: frame data %d bytes exceeds max %d", len(data), WgOverTLSMaxData)
	}
	body := make([]byte, 1+len(data))
	body[0] = typ
	copy(body[1:], data)
	var lenBuf [WgOverTLSHeaderLen]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// ReadFrame reads one framed message, returning its type and data. ok is
// false on a framing error (bad length, oversized body, or read error).
func ReadFrame(r io.Reader) (typ byte, data []byte, err error) {
	var lenBuf [WgOverTLSHeaderLen]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < 1 || uint32(n) > WgOverTLSMaxBody {
		return 0, nil, fmt.Errorf("wgovertls: frame body length %d out of range", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return body[0], body[1:], nil
}

// Result is the per-test outcome the server records and returns to the client.
//
// Src is the address the server actually saw the test arrive from (its public
// IP:port). That is the whole point of the server being the oracle: the client
// inside the NAT doesn't know its own public address, but the server does.
type Result struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Src      string `json:"src"`
	Duration string `json:"duration"`
	Detail   string `json:"detail,omitempty"`
}

// checksum is a single-byte XOR over the frame body. It is not cryptographic —
// it just lets the receiver reject garbage (or an off-by-one framing) instead of
// treating a coincidental 12-byte UDP payload as a valid ACK.
func checksum(b []byte) byte {
	var c byte
	for _, x := range b {
		c ^= x
	}
	return c
}

// EncodeACKRequest builds the 12-byte UDP-ACK request:
//
//	[magic:1][seq:2][client-ts:8][xor:1]
//
// seq is a caller-chosen id the client uses to match the reply. ts is the client's
// unix nanosecond clock at send time, echoed back by the server so the client can
// measure round-trip latency.
func EncodeACKRequest(seq uint16, ts int64) []byte {
	var buf [ReqSize]byte
	buf[0] = MagicReq
	binary.BigEndian.PutUint16(buf[1:3], seq)
	binary.BigEndian.PutUint64(buf[3:11], uint64(ts))
	buf[11] = checksum(buf[:11])
	return buf[:]
}

// DecodeACKRequest parses and validates a request frame. ok is false on bad magic,
// wrong length, or checksum mismatch.
func DecodeACKRequest(b []byte) (seq uint16, ts int64, ok bool) {
	if len(b) != ReqSize || b[0] != MagicReq || checksum(b[:11]) != b[11] {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(b[1:3]), int64(binary.BigEndian.Uint64(b[3:11])), true
}

// EncodeACKResponse builds the 30-byte acknowledgment the server sends back:
//
//	[magic:1][seq:2][client-ts:8][src-ip:16][src-port:2][xor:1]
//
// src is the address the server observed the request coming from; ip4InV6 pads an
// IPv4 address into the 16-byte field.
func EncodeACKResponse(seq uint16, ts int64, src net.IP, srcPort uint16) []byte {
	var buf [RespSize]byte
	buf[0] = MagicResp
	binary.BigEndian.PutUint16(buf[1:3], seq)
	binary.BigEndian.PutUint64(buf[3:11], uint64(ts))
	if ip16 := src.To16(); ip16 != nil {
		copy(buf[11:27], ip16)
	}
	binary.BigEndian.PutUint16(buf[27:29], srcPort)
	buf[29] = checksum(buf[:29])
	return buf[:]
}

// DecodeACKResponse parses and validates an ACK frame, returning the observed
// source IP and port. ok is false on bad magic, wrong length, or checksum mismatch.
func DecodeACKResponse(b []byte) (seq uint16, ts int64, src net.IP, srcPort uint16, ok bool) {
	if len(b) != RespSize || b[0] != MagicResp || checksum(b[:29]) != b[29] {
		return 0, 0, nil, 0, false
	}
	src = make(net.IP, 16)
	copy(src, b[11:27])
	return binary.BigEndian.Uint16(b[1:3]), int64(binary.BigEndian.Uint64(b[3:11])), src, binary.BigEndian.Uint16(b[27:29]), true
}
