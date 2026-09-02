// Package client implements the in-network side of the netdiag harness.
//
// Run executes the tests in order and prints one line per test to w the
// moment the test completes, then prints the conclusion. The src shown on
// each line is the address the server observed — the NAT info the client
// can't know on its own.
package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/rthomazel/netdiag/internal/protocol"
)

// Target holds the five VPS addresses the tests dial. One port per test;
// the CLI derives them from a single host flag, but taking full host:port
// pairs here keeps the package testable on ephemeral local ports.
type Target struct {
	HTTPS   string
	TCP     string
	UDP     string
	WG51820 string // WireGuard endpoint for test 4
	WG443   string // WireGuard endpoint for test 5
}

// Run executes the tests in order, printing each result as it completes
// and the conclusion at the end. Returns the results for exit-code use.
func Run(ctx context.Context, t Target, timeout time.Duration, w io.Writer) []protocol.Result {
	fmt.Fprintln(w, "Client Network Connectivity Test")
	results := make([]protocol.Result, 0, 5)
	tests := []func(ctx context.Context) protocol.Result{
		func(ctx context.Context) protocol.Result { return httpsTest(ctx, t.HTTPS, timeout) },
		func(ctx context.Context) protocol.Result { return tcpTest(ctx, t.TCP, timeout) },
		func(ctx context.Context) protocol.Result { return udpTest(ctx, t.UDP, timeout) },
	}
	for _, test := range tests {
		res := test(ctx)
		results = append(results, res)
		printLine(w, res, label(res, t))
	}
	// Tests 4 and 5 need the server's WireGuard public keys, fetched over
	// the HTTPS control plane. If that fetch fails the WG tests are
	// reported as untestable rather than run against nothing.
	if ctx.Err() == nil {
		keys, err := wgFetchKeys(ctx, t.HTTPS, timeout)
		if err != nil {
			for _, name := range []string{protocol.TestWG51820, protocol.TestWG443} {
				res := protocol.Result{Name: name}
				res.Status = protocol.StatusFail
				res.Detail = "untestable: could not fetch server wg keys: " + err.Error()
				results = append(results, res)
				printLine(w, res, label(res, t))
			}
		} else {
			wgTests := []struct {
				name   string
				pubHex string
				addr   string
				subnet protocol.Subnet
			}{
				{protocol.TestWG51820, keys.WG51820, t.WG51820, protocol.WGSubnet51820},
				{protocol.TestWG443, keys.WG443, t.WG443, protocol.WGSubnet443},
			}
			for _, tt := range wgTests {
				res := wgTest(ctx, tt.name, tt.addr, t.HTTPS, tt.pubHex, tt.subnet, timeout)
				results = append(results, res)
				printLine(w, res, label(res, t))
			}
		}
	}
	fmt.Fprintln(w)
	printConclusion(w, results)
	return results
}

// AnyFailed reports whether any result is not a pass.
func AnyFailed(results []protocol.Result) bool {
	for _, r := range results {
		if r.Status != protocol.StatusPass {
			return true
		}
	}
	return false
}

func label(res protocol.Result, t Target) string {
	switch res.Name {
	case protocol.TestHTTPS443:
		return "HTTPS TCP/" + portOf(t.HTTPS)
	case protocol.TestTCP8443:
		return "TCP/" + portOf(t.TCP)
	case protocol.TestUDP:
		return "UDP/" + portOf(t.UDP)
	case protocol.TestWG51820:
		return "WireGuard UDP/" + portOf(t.WG51820)
	case protocol.TestWG443:
		return "WireGuard UDP/" + portOf(t.WG443)
	}
	return res.Name
}

func printLine(w io.Writer, res protocol.Result, label string) {
	status := "FAIL"
	if res.Status == protocol.StatusPass {
		status = "PASS"
	}
	line := fmt.Sprintf("[%s] %-16s src=%-21s", status, label, orDash(res.Src))
	if res.Status == protocol.StatusPass {
		line += "  rtt=" + res.Duration
	}
	if res.Detail != "" {
		line += "  " + res.Detail
	}
	fmt.Fprintln(w, line)
}

func printConclusion(w io.Writer, results []protocol.Result) {
	failed := 0
	for _, r := range results {
		if r.Status != protocol.StatusPass {
			failed++
		}
	}
	fmt.Fprintln(w, "Conclusion:")
	if failed == 0 {
		fmt.Fprintln(w, "WireGuard handshake works on both standard and non-standard ports. Direct WireGuard connectivity appears viable (tests 1-5).")
		return
	}
	fmt.Fprintf(w, "%d of %d tests failed - the FAIL lines above show where the network blocks us.\n", failed, len(results))
}

func httpsTest(ctx context.Context, addr string, timeout time.Duration) protocol.Result {
	start := time.Now()
	res := protocol.Result{Name: protocol.TestHTTPS443}
	// InsecureSkipVerify: the test measures reachability, not the certificate.
	cli := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/probe", nil)
	if err != nil {
		return fail(res, err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return fail(res, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(res, fmt.Errorf("status %d", resp.StatusCode))
	}
	var out protocol.Result
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return fail(res, fmt.Errorf("bad response from server: %w", err))
	}
	return pass(res, out.Src, time.Since(start))
}

func tcpTest(ctx context.Context, addr string, timeout time.Duration) protocol.Result {
	start := time.Now()
	res := protocol.Result{Name: protocol.TestTCP8443}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fail(res, err)
	}
	defer conn.Close()
	conn.SetDeadline(deadlineFor(ctx, timeout))
	if _, err := conn.Write(protocol.EncodeACKRequest(1, start.UnixNano())); err != nil {
		return fail(res, err)
	}
	return ackRoundTrip(conn, res, start)
}

func udpTest(ctx context.Context, addr string, timeout time.Duration) protocol.Result {
	start := time.Now()
	res := protocol.Result{Name: protocol.TestUDP}
	dst, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fail(res, err)
	}
	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return fail(res, err)
	}
	defer conn.Close()
	conn.SetReadDeadline(deadlineFor(ctx, timeout))
	if _, err := conn.Write(protocol.EncodeACKRequest(1, start.UnixNano())); err != nil {
		return fail(res, err)
	}
	return ackRoundTrip(conn, res, start)
}

// ackRoundTrip reads and validates one ACK response frame; the observed
// source IP:port it carries is what the report shows.
func ackRoundTrip(conn net.Conn, res protocol.Result, start time.Time) protocol.Result {
	buf := make([]byte, protocol.RespSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fail(res, err)
	}
	_, _, ip, port, ok := protocol.DecodeACKResponse(buf)
	if !ok {
		return fail(res, fmt.Errorf("bad response frame from server"))
	}
	src := net.JoinHostPort(ip.String(), strconv.FormatInt(int64(port), 10))
	return pass(res, src, time.Since(start))
}

func deadlineFor(ctx context.Context, timeout time.Duration) time.Time {
	d := time.Now().Add(timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		d = cd
	}
	return d
}

func pass(res protocol.Result, src string, d time.Duration) protocol.Result {
	res.Status = protocol.StatusPass
	res.Src = src
	res.Duration = roundTrip(d)
	return res
}

func fail(res protocol.Result, err error) protocol.Result {
	res.Status = protocol.StatusFail
	res.Detail = err.Error()
	return res
}

// roundTrip renders sub-millisecond round trips in µs so local runs don't
// read as 0s.
func roundTrip(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", int64(d/time.Microsecond))
	}
	return d.Round(time.Millisecond).String()
}

func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return addr
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
