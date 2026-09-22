// Package server implements the VPS side of the netdiag test harness.
//
// One listener per named test. The destination port identifies the test, so
// the client needs no extra signaling: a request to the HTTPS address is the
// HTTPS test, a connection to the TCP address is the arbitrary-TCP test, a
// datagram to the UDP address is the UDP test.
//
// Each listener logs the source IP:port it observes (the NAT info the VPS
// console report is built from) and answers the client over the same channel
// the test arrived on, so the client never needs a second port to reach.
package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/wgtest"
)

// readTimeout bounds how long the listeners wait for a client frame before
// giving up on that connection or datagram.
const readTimeout = 5 * time.Second

// Config holds the listen addresses for the test listeners.
type Config struct {
	HTTPS   string // Plain TCP address shared by the HTTPS test and the WireGuard-over-TLS test
	TCP     string
	UDP     string
	WG51820  string // UDP address for the WireGuard test 4 listener
	WG443    string // UDP address for the WireGuard test 5 listener
	WGAbitrary string // UDP address for the WireGuard test 6 listener (arbitrary port)
}

// Server holds the pre-bound listeners that Serve runs.
type Server struct {
	HTTPS net.Listener // Plain TCP listener shared by the HTTPS test and test 9
	TCP   net.Listener
	UDP   *net.UDPConn
	WG    *WG
	Cert  tls.Certificate // Certificate the shared listener terminates TLS with
}

// Run binds the listeners from cfg and serves them until ctx is canceled.
func Run(ctx context.Context, cfg Config) error {
	cert, err := SelfSignedCert()
	if err != nil {
		return fmt.Errorf("self-signed cert: %w", err)
	}

	// The HTTPS port is shared with the WireGuard-over-TLS test: one plain TCP
	// listener is accepted on cfg.HTTPS, TLS is terminated per connection, and
	// the SNI decides whether the connection is an ordinary HTTPS request or a
	// WireGuard-over-TLS handshake. This is the whole point of test 9 - the
	// client dials the same port with a distinctive SNI.
	httpsLn, err := net.Listen("tcp", cfg.HTTPS)
	if err != nil {
		return fmt.Errorf("https %s: %w", cfg.HTTPS, err)
	}
	tcpLn, err := net.Listen("tcp", cfg.TCP)
	if err != nil {
		httpsLn.Close()
		return fmt.Errorf("tcp %s: %w", cfg.TCP, err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.UDP)
	if err != nil {
		httpsLn.Close()
		tcpLn.Close()
		return fmt.Errorf("udp %s: %w", cfg.UDP, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		httpsLn.Close()
		tcpLn.Close()
		udpConn.Close()
		return fmt.Errorf("udp %s: %w", cfg.UDP, err)
	}

	wg, err := NewWG(cfg.WG51820, cfg.WG443, cfg.WGAbitrary)
	if err != nil {
		httpsLn.Close()
		tcpLn.Close()
		udpConn.Close()
		return err
	}

	return Serve(ctx, Server{HTTPS: httpsLn, TCP: tcpLn, UDP: udpConn, WG: wg, Cert: cert})
}

// Serve runs the listeners until ctx is canceled, then closes them. It takes
// pre-bound listeners so tests can run the harness on ephemeral ports.
func Serve(ctx context.Context, s Server) error {
	go func() {
		<-ctx.Done()
		s.HTTPS.Close()
		s.TCP.Close()
		s.UDP.Close()
		if s.WG != nil {
			s.WG.Close()
		}
	}()
	go serveHTTPS(ctx, s.HTTPS, s.WG, s.Cert)
	go acceptTCP(ctx, s.TCP)
	go readUDP(ctx, s.UDP)

	<-ctx.Done()
	return nil
}

// serveHTTPS is the shared listener. It terminates TLS per connection and
// routes on the ServerName from the ClientHello: the marker SNI selects the
// WireGuard-over-TLS handshake (test 9), any other name is served by the
// ordinary HTTPS control plane. Sharing one listener is the point of test 9 -
// the client dials the same port the HTTPS test uses.
func serveHTTPS(ctx context.Context, ln net.Listener, wg *WG, cert tls.Certificate) {
	log.Printf("listening for test %s on %s (self-signed TLS, shared with %s)", protocol.TestHTTPS443, ln.Addr(), protocol.TestWGOverTLS)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("https: accept: %v", err)
			}
			return
		}
		go serveHTTPSConn(ctx, conn, wg, tlsConfig)
	}
}

// serveHTTPSConn terminates the TLS handshake, inspects the SNI, and routes the
// connection to the WireGuard-over-TLS handler or the HTTPS control plane.
func serveHTTPSConn(ctx context.Context, raw net.Conn, wg *WG, tlsConfig *tls.Config) {
	defer raw.Close()
	tlsConn := tls.Server(raw, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	sni := tlsConn.ConnectionState().ServerName
	if sni == protocol.MarkerSNI {
		handleWGOverTLS(ctx, tlsConn, wg)
		return
	}
	serveHTTPSRequest(ctx, tlsConn, wg)
}

// serveHTTPSRequest serves a single HTTPS request read from the connection and
// writes the response back. The client uses DisableKeepAlives, so one request
// per connection is all the harness ever needs.
func serveHTTPSRequest(ctx context.Context, conn *tls.Conn, wg *WG) {
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	// http.ReadRequest does not set req.RemoteAddr - the real net/http server
	// does, because it accepts the connection. We must set it here so the
	// /wg control plane can report the observed source address (the NAT info
	// the report is built from).
	req.RemoteAddr = conn.RemoteAddr().String()
	w := &connResponseWriter{conn: conn}
	httpsHandler(wg).ServeHTTP(w, req)
	w.finish()
}

// connResponseWriter is a minimal http.ResponseWriter that writes an
// HTTP/1.1 response over a single connection. The standard http.Server is
// unavailable for per-connection TLS here (its per-connection serve helpers
// are not exposed in Go 1.26), so the client's request/response are served
// manually: one request is read, the mux serves it, and the response is
// streamed and the connection is closed to signal the end.
type connResponseWriter struct {
	conn      *tls.Conn
	status    int
	hasStatus bool
	header    http.Header
	wroteHdr  bool
}

func (w *connResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

// WriteHeader records the status code. Only the first call takes effect,
// matching the http.ResponseWriter contract.
func (w *connResponseWriter) WriteHeader(code int) {
	if w.hasStatus {
		return
	}
	w.status = code
	w.hasStatus = true
}

// flushHeaders writes the status line and headers on the first write.
func (w *connResponseWriter) flushHeaders() {
	if w.wroteHdr {
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", w.status, http.StatusText(w.status))
	if w.header != nil {
		_ = w.header.Write(w.conn)
	}
	_, _ = w.conn.Write([]byte("\r\n"))
	w.wroteHdr = true
}

// Write streams the body. The status line and headers are written on the first
// Write if they have not been written yet, which is the common case for the
// JSON handlers here.
func (w *connResponseWriter) Write(b []byte) (int, error) {
	w.flushHeaders()
	return w.conn.Write(b)
}

// finish writes the headers if needed, then closes the connection to signal
// the end of the response. The client uses DisableKeepAlives, so it reads the
// response until the connection closes.
func (w *connResponseWriter) finish() {
	w.flushHeaders()
	_ = w.conn.Close()
}

// httpsHandler is the listener for test https443. Any request is answered
// with a JSON Result carrying the source address it observed. The /wg routes
// are the WireGuard control plane: key distribution, client registration, and
// status readback for tests 4 and 5.
func httpsHandler(wg *WG) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s from %s", protocol.TestHTTPS443, r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		res := protocol.Result{Name: protocol.TestHTTPS443, Status: protocol.StatusPass, Src: r.RemoteAddr}
		_ = json.NewEncoder(w).Encode(res)
	})
	if wg != nil {
		mux.HandleFunc("/wg", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(wg.Keys())
		})
		mux.HandleFunc("/wg/register", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req wgRegisterReq
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				http.Error(w, "bad request body", http.StatusBadRequest)
				return
			}
			pub, err := hex.DecodeString(req.PublicKey)
			if err != nil || len(pub) != 32 {
				http.Error(w, "public_key must be 32 hex-encoded bytes", http.StatusBadRequest)
				return
			}
			if !wg.Known(req.Test) {
				http.Error(w, "unknown test", http.StatusBadRequest)
				return
			}
			if err := wg.Register(req.Test, [32]byte(pub)); err != nil {
				log.Printf("wg register: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("/wg/status/", func(w http.ResponseWriter, r *http.Request) {
			name := strings.TrimPrefix(r.URL.Path, "/wg/status/")
			var st wgtest.Status
			var err error
			if name == protocol.TestWGOverTLS {
				st, err = wg.statusOverTLS()
			} else {
				st, err = wg.Status(name)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(st)
		})
	}
	return mux
}

// wgRegisterReq is the client registration body: which WG test the client
// will talk to, and the device public key it generated for it.
type wgRegisterReq struct {
	Test      string `json:"test"`
	PublicKey string `json:"public_key"`
}

// acceptTCP is the listener for test tcp8443. It speaks the same ACK
// exchange as the UDP test: one request frame in, one response frame out.
func acceptTCP(ctx context.Context, ln net.Listener) {
	log.Printf("listening for test %s on %s", protocol.TestTCP8443, ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("tcp: accept: %v", err)
			}
			return
		}
		go serveTCP(conn)
	}
}

func serveTCP(conn net.Conn) {
	defer conn.Close()
	addr := conn.RemoteAddr().(*net.TCPAddr)
	log.Printf("%s from %s", protocol.TestTCP8443, addr)
	conn.SetDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, protocol.ReqSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	seq, ts, ok := protocol.DecodeACKRequest(buf)
	if !ok {
		log.Printf("%s: bad frame from %s", protocol.TestTCP8443, addr)
		return
	}
	_, _ = conn.Write(protocol.EncodeACKResponse(seq, ts, addr.IP, uint16(addr.Port)))
}

// readUDP is the listener for test udp. It acknowledges every valid request
// datagram, echoing the sequence and client timestamp back and stamping in
// the source address it observed.
func readUDP(ctx context.Context, conn *net.UDPConn) {
	log.Printf("listening for test %s on %s", protocol.TestUDP, conn.LocalAddr())
	buf := make([]byte, 512)
	for {
		conn.SetReadDeadline(time.Now().Add(readTimeout))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() == nil {
				log.Printf("udp: read: %v", err)
			}
			return
		}
		seq, ts, ok := protocol.DecodeACKRequest(buf[:n])
		if !ok {
			log.Printf("%s: bad frame from %s", protocol.TestUDP, addr)
			continue
		}
		log.Printf("%s from %s", protocol.TestUDP, addr)
		_, _ = conn.WriteToUDP(protocol.EncodeACKResponse(seq, ts, addr.IP, uint16(addr.Port)), addr)
	}
}

// SelfSignedCert generates an in-memory certificate for the HTTPS listener.
// The client skips verification: the test measures reachability, not the
// certificate.
func SelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "netdiag"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
