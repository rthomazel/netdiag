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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/rthomazel/netdiag/internal/protocol"
)

// readTimeout bounds how long the listeners wait for a client frame before
// giving up on that connection or datagram.
const readTimeout = 5 * time.Second

// Config holds the listen addresses for the three test listeners.
type Config struct {
	HTTPS string
	TCP   string
	UDP   string
}

// Server holds the pre-bound listeners that Serve runs.
type Server struct {
	HTTPS net.Listener
	TCP   net.Listener
	UDP   *net.UDPConn
}

// Run binds the listeners from cfg and serves them until ctx is canceled.
func Run(ctx context.Context, cfg Config) error {
	cert, err := SelfSignedCert()
	if err != nil {
		return fmt.Errorf("self-signed cert: %w", err)
	}

	tlsLn, err := tls.Listen("tcp", cfg.HTTPS, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return fmt.Errorf("https %s: %w", cfg.HTTPS, err)
	}
	tcpLn, err := net.Listen("tcp", cfg.TCP)
	if err != nil {
		tlsLn.Close()
		return fmt.Errorf("tcp %s: %w", cfg.TCP, err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", cfg.UDP)
	if err != nil {
		tlsLn.Close()
		tcpLn.Close()
		return fmt.Errorf("udp %s: %w", cfg.UDP, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		tlsLn.Close()
		tcpLn.Close()
		return fmt.Errorf("udp %s: %w", cfg.UDP, err)
	}

	return Serve(ctx, Server{HTTPS: tlsLn, TCP: tcpLn, UDP: udpConn})
}

// Serve runs the three listeners until ctx is canceled, then closes them.
// It takes pre-bound listeners so tests can run the harness on ephemeral ports.
func Serve(ctx context.Context, s Server) error {
	go func() {
		<-ctx.Done()
		s.HTTPS.Close()
		s.TCP.Close()
		s.UDP.Close()
	}()
	go serveHTTPS(ctx, s.HTTPS)
	go acceptTCP(ctx, s.TCP)
	go readUDP(ctx, s.UDP)

	<-ctx.Done()
	return nil
}

// serveHTTPS is the listener for test https443. Any request is answered with
// a JSON Result carrying the source address it observed.
func serveHTTPS(ctx context.Context, ln net.Listener) {
	log.Printf("listening for test %s on %s (self-signed TLS)", protocol.TestHTTPS443, ln.Addr())
	srv := &http.Server{Handler: httpsHandler()}
	// Closing the listener at shutdown makes Serve return a non-nil, non-ErrServerClosed
	// error; the ctx check keeps that out of the log.
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
		log.Printf("https: %v", err)
	}
}

func httpsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s from %s", protocol.TestHTTPS443, r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		res := protocol.Result{Name: protocol.TestHTTPS443, Status: protocol.StatusPass, Src: r.RemoteAddr}
		_ = json.NewEncoder(w).Encode(res)
	})
	return mux
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
