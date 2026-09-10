package client_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rthomazel/netdiag/internal/client"
	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/server"
)

// startServer runs the real server package on ephemeral loopback ports and
// returns the client targets that point at it, including the two WireGuard
// devices on their actual (read-back) ports.
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
	wg, err := server.NewWG("127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wg: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx, server.Server{HTTPS: tlsLn, TCP: tcpLn, UDP: udpLn, WG: wg})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	p51820, err := wg.Port(protocol.TestWG51820)
	if err != nil {
		t.Fatal(err)
	}
	p443, err := wg.Port(protocol.TestWG443)
	if err != nil {
		t.Fatal(err)
	}

	return client.Target{
		HTTPS:   tlsLn.Addr().String(),
		TCP:     tcpLn.Addr().String(),
		UDP:     udpLn.LocalAddr().String(),
		WG51820: "127.0.0.1:" + strconv.Itoa(p51820),
		WG443:   "127.0.0.1:" + strconv.Itoa(p443),
	}
}

func TestRunAgainstRealServer(t *testing.T) {
	var out bytes.Buffer
	results := client.Run(context.Background(), startServer(t), 5*time.Second, 2*time.Second, 5*time.Second, &out)

	if len(results) != 7 {
		t.Fatalf("len(results) = %d, want 7", len(results))
	}
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
		"[PASS] WireGuard UDP/",
		"[PASS] WireGuard persistent",
		"[PASS] WireGuard bidir",
		"src=127.0.0.1:",
		"rtt=",
		"Conclusion:",
		"tests 1-7",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
}

func TestRunAgainstNothing(t *testing.T) {
	// Nothing listens on these ports: every test must fail cleanly and the
	// report must still render (detail set, conclusion counts the failures).
	// The WireGuard tests fail as untestable: with no HTTPS control plane
	// there are no server keys to fetch.
	var out bytes.Buffer
	results := client.Run(context.Background(), client.Target{
		HTTPS: "127.0.0.1:1", TCP: "127.0.0.1:1", UDP: "127.0.0.1:1",
		WG51820: "127.0.0.1:1", WG443: "127.0.0.1:1",
	}, 500*time.Millisecond, 500*time.Millisecond, 500*time.Millisecond, &out)

	if len(results) != 7 {
		t.Fatalf("len(results) = %d, want 7", len(results))
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
	if !strings.Contains(report, "7 of 7 tests failed") {
		t.Errorf("report missing failure conclusion:\n%s", report)
	}
}

// TestWG51820FailsMarksSixSevenUntestable runs the full suite against a live
// server but points the 51820 WireGuard endpoint at a dead port, so test 4's
// handshake can never complete. Tests 6 and 7 ride on test 4's device, so
// they must be reported untestable (not failed on their own terms), matching
// the key-fetch-failure pattern in Run.
func TestWG51820FailsMarksSixSevenUntestable(t *testing.T) {
	tgt := startServer(t)
	tgt.WG51820 = "127.0.0.1:1" // nothing listens here: test 4 can't complete

	var out bytes.Buffer
	results := client.Run(context.Background(), tgt, time.Second, 500*time.Millisecond, time.Second, &out)

	if len(results) != 7 {
		t.Fatalf("len(results) = %d, want 7", len(results))
	}
	byName := map[string]protocol.Result{}
	for _, r := range results {
		byName[r.Name] = r
	}
	if r := byName[protocol.TestWG51820]; r.Status != protocol.StatusFail {
		t.Errorf("wg51820 = %s, want fail (dead port)", r.Status)
	}
	for _, name := range []string{protocol.TestPersistent, protocol.TestBidir} {
		r := byName[name]
		if r.Status != protocol.StatusFail {
			t.Errorf("%s = %s, want fail (untestable)", name, r.Status)
		}
		if !strings.Contains(r.Detail, "untestable") {
			t.Errorf("%s detail = %q, want untestable", name, r.Detail)
		}
	}
	if r := byName[protocol.TestWG443]; r.Status != protocol.StatusPass {
		t.Errorf("wg443 = %s, want pass (endpoint still live)", r.Status)
	}
}
