package client_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rthomazel/netdiag/internal/client"
	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/server"
)

// startServer runs the real server package on ephemeral loopback ports and
// returns the client targets that point at it.
func startServer(t *testing.T) client.Target {
	t.Helper()

	cert, err := server.SelfSignedCert()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx, server.Server{HTTPS: tlsLn, TCP: tcpLn, UDP: udpLn})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return client.Target{HTTPS: tlsLn.Addr().String(), TCP: tcpLn.Addr().String(), UDP: udpLn.LocalAddr().String()}
}

func TestRunAgainstRealServer(t *testing.T) {
	var out bytes.Buffer
	results := client.Run(context.Background(), startServer(t), time.Second, &out)

	for _, res := range results {
		if res.Status != protocol.StatusPass {
			t.Errorf("test %s = %s: %s", res.Name, res.Status, res.Detail)
		}
		if !strings.HasPrefix(res.Src, "127.0.0.1:") {
			t.Errorf("test %s src = %q, want 127.0.0.1:*", res.Name, res.Src)
		}
	}
	if client.AnyFailed(results) {
		t.Fatal("AnyFailed = true")
	}
	report := out.String()
	for _, want := range []string{
		"Client Network Connectivity Test",
		"[PASS] HTTPS TCP/",
		"[PASS] TCP/",
		"[PASS] UDP/",
		"src=127.0.0.1:",
		"rtt=",
		"Conclusion:",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
}

func TestRunAgainstNothing(t *testing.T) {
	// Nothing listens on these ports: every test must fail cleanly and the
	// report must still render (detail set, conclusion counts the failures).
	var out bytes.Buffer
	results := client.Run(context.Background(), client.Target{
		HTTPS: "127.0.0.1:1", TCP: "127.0.0.1:1", UDP: "127.0.0.1:1",
	}, 500*time.Millisecond, &out)

	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	for _, res := range results {
		if res.Status != protocol.StatusFail {
			t.Errorf("test %s = %s, want fail", res.Name, res.Status)
		}
		if res.Detail == "" {
			t.Errorf("test %s: empty detail on failure", res.Name)
		}
	}
	report := out.String()
	if !strings.Contains(report, "3 of 3 tests failed") {
		t.Errorf("report missing failure conclusion:\n%s", report)
	}
}
