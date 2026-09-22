// Package wgtest provides a WireGuard-over-TLS conn.Bind.
//
// The WireGuard-over-TLS handshake test (test 9) carries WireGuard packets
// inside an ordinary TLS connection over TCP/443. The transport is a single
// *tls.Conn: the WireGuard device's receive path is bridged to a reader
// goroutine that reads framed packets from the connection, and its send path
// is bridged to Write, which frames packets as they are written out.
//
// TLS reads do not preserve message boundaries, so the reader does exact reads
// (4-byte big-endian length, then that many payload bytes) and only ever
// delivers complete WireGuard packets to the device. TLS read and write use
// separate mutexes, so the device can send handshake packets while the reader
// delivers replies and they are not serialized.
package wgtest

import (
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/rthomazel/netdiag/internal/protocol"
)

// TLSBind is a conn.Bind over a *tls.Conn. Packets written through Send are
// framed and written to the connection; the device's receive path is fed by
// readLoop, which reads framed packets from the connection and delivers them
// to the recv function the device installed via Open.
//
// WireGuard's BindUpdate runs Close() then Open() together - on bring-up and
// again on every rekey - so a single TLSBind can spawn several readLoop
// goroutines over its lifetime. To keep each reader's lifecycle isolated,
// every Open() installs a fresh bindGen, and each reader settles only its own
// readerExited. The current generation is exposed through cur, an immutable
// snapshot that recv, Send and ReaderExited read without locking.
type TLSBind struct {
	tlsConn *tls.Conn
	cur     atomic.Pointer[bindGen]
	mu      sync.Mutex
	opened  bool
}

// bindGen bundles the per-generation channels. It is immutable after
// creation, so recv, Send and ReaderExited can read its channels without
// holding mu.
type bindGen struct {
	packets      chan []byte
	closed       chan struct{} // closed by Close; recv and Send observe it
	readerExited chan struct{} // closed exactly once, by this gen's readLoop
	closeOnce    sync.Once     // guards a single close of closed
}

// NewTLSBind wraps an already-handshaken *tls.Conn. The device must call Open
// to install its recv and start the reader goroutine before any packets flow.
func NewTLSBind(tlsConn *tls.Conn) *TLSBind {
	return &TLSBind{tlsConn: tlsConn}
}

// ReaderExited returns a channel that is closed when the current reader
// goroutine has exited. The server handler waits on it to know the client has
// finished the handshake exchange and closed the connection. It returns nil
// before the first Open, so a caller may wait on it safely at any time.
func (b *TLSBind) ReaderExited() <-chan struct{} {
	g := b.cur.Load()
	if g == nil {
		return nil
	}
	return g.readerExited
}

// readLoop reads framed packets from the connection and delivers them to the
// recv function. It exits when the bind is closed, or the reader encounters an
// error. It starts once, when Open runs, so the caller can exchange the
// key-exchange control frames before the device begins consuming the packet
// stream.
//
// g is passed in from Open and captured for the life of the goroutine. It is
// never reloaded from cur: Close() waits for this reader to exit before the
// next Open() installs a fresh generation, so the reader always watches its
// own generation's closed channel and settles its own readerExited regardless
// of any later swaps.
func (b *TLSBind) readLoop(g *bindGen) {
	// readerExited is the public signal the server waits on (ReaderExited)
	// and recv watches; closing it marks this readLoop as gone. Each
	// generation has its own readerExited, closed only by its own readLoop,
	// so the Close()-then-Open() cycle that WireGuard runs inside BindUpdate
	// can never double-close a channel.
	defer close(g.readerExited)
	for {
		select {
		case <-g.closed:
			return
		default:
		}
		typ, data, err := protocol.ReadFrame(b.tlsConn)
		if err != nil {
			return
		}
		if typ != protocol.WgOverTLSPacketType {
			continue
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		select {
		case g.packets <- buf:
		case <-g.closed:
			return
		}
	}
}

// Open installs the device's recv function and starts the reader goroutine.
// A TLS bind has no port; 0 is returned. Open must be called before any
// packets arrive, which is exactly when the WireGuard device calls it while
// being brought up.
func (b *TLSBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Held across the whole critical section so Open and Close cannot
	// interleave: WireGuard runs Close() then Open() back-to-back inside
	// BindUpdate, and the guard on b.opened must be reliable.
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.opened {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	// Each generation owns its own channels, so a reader spawned by a later
	// Open never touches the readerExited of the one it supersedes.
	g := &bindGen{
		packets:      make(chan []byte, conn.IdealBatchSize),
		closed:       make(chan struct{}),
		readerExited: make(chan struct{}),
	}
	b.cur.Store(g)
	b.opened = true
	go b.readLoop(g)
	return []conn.ReceiveFunc{b.recv}, 0, nil
}

// recv delivers buffered packets to the device. It blocks until a packet is
// available, the bind is closed, or recv is called after Close. A single packet
// is delivered per call, matching the device's receive contract. The closed
// signal is always checked first so device teardown never blocks on buffered
// packets.
func (b *TLSBind) recv(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	g := b.cur.Load()
	if g == nil {
		return 0, net.ErrClosed
	}
	select {
	case <-g.closed:
		return 0, net.ErrClosed
	default:
	}
	select {
	case buf := <-g.packets:
		// Copy the decoded WireGuard packet into the buffer the device
		// allocated, in place, and report its length. WireGuard's receive
		// routine reads packet data from bufsArrs[i][:size] - the buffer it
		// handed us via bufs[i] - so the bytes must land in that backing
		// array, not merely replace the slice header recv holds. Writing to
		// packets[0] only would leave the device reading the untouched
		// (zeroed) buffer, which it would reject as an unknown message type.
		if len(buf) > len(packets[0]) {
			return 0, io.ErrShortBuffer
		}
		copy(packets[0], buf)
		sizes[0] = len(buf)
		eps[0] = b.endpoint()
		return 1, nil
	case <-g.closed:
		return 0, net.ErrClosed
	}
}

// endpoint returns the remote address of the TLS connection as a conn.Endpoint.
// The server bind reports the client's address, which is the NAT observation
// the report is built from; the client bind's endpoint is cosmetic.
func (b *TLSBind) endpoint() conn.Endpoint {
	ap, err := netip.ParseAddrPort(b.tlsConn.RemoteAddr().String())
	if err != nil {
		ap = netip.AddrPort{}
	}
	return &tlsEndpoint{AddrPort: ap}
}

// Send frames each packet and writes it to the connection. Each call may carry
// several packets; framing preserves the boundaries the reader needs.
func (b *TLSBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	// Watch the current generation's closed channel rather than the unlocked
	// b.opened: Send runs on the device's send path with no lock available, so
	// it must rely on the channel signal that Close publishes.
	g := b.cur.Load()
	if g == nil {
		return net.ErrClosed
	}
	select {
	case <-g.closed:
		return net.ErrClosed
	default:
	}
	for _, buf := range bufs {
		if err := protocol.WriteFrame(b.tlsConn, protocol.WgOverTLSPacketType, buf); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint parses a host:port string into a tlsEndpoint. For the TLS
// bind the endpoint is only used cosmetically.
func (b *TLSBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &tlsEndpoint{AddrPort: ap}, nil
}

// BatchSize is the maximum number of buffers the device will pass to Send.
// The WireGuard device uses the max of the bind batch size and the TUN batch
// size (which is 1), so the bind must advertise a batch size of at least the
// device's IdealBatchSize to never be asked to send more than it can.
func (b *TLSBind) BatchSize() int {
	return conn.IdealBatchSize
}

// SetMark is a no-op for the TLS bind: there is no socket to mark.
func (b *TLSBind) SetMark(mark uint32) error {
	return nil
}

// Close signals the active reader to stop. It is safe to call multiple
// times: only the first call settles the current generation.
//
// WireGuard's BindUpdate runs Close() then Open() together - on bring-up and
// again whenever the key is reloaded - so Close must let the current reader
// go away before returning. Otherwise the Open() that follows would launch a
// second reader whose deferred close(readerExited) would collide with the
// first one and panic. Waiting here also means the next Open starts exactly
// one reader, exactly as StdNetBind guarantees by nil-ing its socket handles
// before reopening.
//
// The underlying TLS connection is deliberately NOT closed here: it is the
// shared transport that WireGuard packets ride on, and WireGuard reuses it
// for the very Open() that follows this Close(). Closing it would strand the
// rebind. Instead Close() imposes a past read deadline on the connection, so
// the blocked ReadFrame in readLoop fails immediately and the reader exits
// without touching the connection's lifetime. The caller owns closing the
// connection (the handler's defer raw.Close() once the handshake is done).
func (b *TLSBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.opened {
		return nil
	}
	g := b.cur.Load()
	if g == nil {
		return nil
	}
	// Close this generation's closed channel exactly once so the reader
	// unblocks and recv/Send observe the shutdown.
	g.closeOnce.Do(func() {
		close(g.closed)
		// Impose a past read deadline so readLoop's in-progress ReadFrame
		// returns at once. This unblocks the reader without closing the
		// transport, letting the Open() that follows reuse the connection.
		_ = b.tlsConn.SetReadDeadline(time.Now().Add(-time.Second))
	})
	// Wait for this generation's reader to fully unwind before clearing
	// opened, so the Open() that BindUpdate runs next starts a single clean
	// reader. (readerExited is closed by readLoop's final defer, i.e. once it
	// has returned, so unblocking here guarantees no second reader can be born
	// alongside the first.)
	<-g.readerExited
	// Clear the read deadline. It was a transient trick to wake the reader
	// that is now gone; if left in place it would make the next reader's
	// very first ReadFrame fail instantly.
	_ = b.tlsConn.SetReadDeadline(time.Time{})
	// Leave cur pointing at this settled generation: recv, Send and
	// ReaderExited remain valid against it (it is already closed), and the
	// next Open() installs a fresh generation on top. Keeping cur non-nil
	// also guarantees no goroutine can observe a nil generation and bail out
	// of readLoop before settling its readerExited.
	b.opened = false
	return nil
}

// tlsEndpoint is a conn.Endpoint backed by a netip.AddrPort. It mirrors the
// StdNetEndpoint contract closely enough for the diagnostic device, which
// only uses DstToString, DstToBytes, DstIP and SrcIP to record the client's
// observed source address.
type tlsEndpoint struct {
	netip.AddrPort
}

// ClearSrc is a no-op; the TLS endpoint has no sticky source to clear.
func (e *tlsEndpoint) ClearSrc() {}

// SrcToString returns the source address as a string.
func (e *tlsEndpoint) SrcToString() string {
	return e.AddrPort.String()
}

// DstToString returns the destination address as a string.
func (e *tlsEndpoint) DstToString() string {
	return e.AddrPort.String()
}

// DstToBytes returns the marshaled destination address.
func (e *tlsEndpoint) DstToBytes() []byte {
	buf, _ := e.AddrPort.MarshalBinary()
	return buf
}

// DstIP returns the destination address.
func (e *tlsEndpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

// SrcIP returns the source address.
func (e *tlsEndpoint) SrcIP() netip.Addr {
	return e.AddrPort.Addr()
}
