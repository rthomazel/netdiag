package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rthomazel/netdiag/internal/client"
	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/wgtest"
)

func main() {
	server := flag.String("server", "", "VPS host or IP (required)")
	timeout := flag.Duration("timeout", 5*time.Second, "per-test timeout")
	idle := flag.Duration("idle", protocol.DefaultPersistentWindow,
		"test 6 idle window (the persistent-NAT diagnostic; 60s is the deliberate default)")
	reqTimeout := flag.Duration("reqtimeout", 10*time.Second, "timeout per HTTPS control-plane request (key fetch, register, status poll)")
	wgArbitrary := flag.String("wgarbitrary", "1194", "arbitrary UDP port for the extra WireGuard handshake test (must match the server's NETDIAG_WG_ARBITRARY)")
	debug := flag.Bool("debug", false,
		"emit WireGuard DEBUG: lines and tee all output to network-test-debug-<unixtimestamp>.txt in the current directory")
	flag.Parse()

	runOut := os.Stdout
	var tee *stdoutTee
	if *debug {
		trace, err := openDebugTrace()
		if err != nil {
			fmt.Fprintf(os.Stderr, "netdiag-client: %v\n", err)
			return
		}
		tee, err = newStdoutTee(trace)
		if err != nil {
			_ = trace.Close()
			fmt.Fprintf(os.Stderr, "netdiag-client: %v\n", err)
			return
		}
		os.Stdout = tee.pipeWriter
		runOut = os.Stdout
		fmt.Fprintf(os.Stderr, "netdiag-client: debug trace written to %s\n", trace.Name())
	}
	// WireGuard device logging stays silent unless -debug asks for it; the
	// server opts back into verbose logging to preserve its historical output.
	wgtest.SetDebug(*debug)

	if *server == "" {
		fmt.Fprintln(os.Stderr, "usage: netdiag-client -server <vps-ip> [-timeout 5s] [-idle 1m] [-wgarbitrary 1194] [-debug]")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	results := client.Run(ctx, client.Target{
		HTTPS:      *server + ":443",
		TCP:        *server + ":8443",
		UDP:        *server + ":60000",
		WG51820:    *server + ":51820",
		WG443:      *server + ":443",
		WGAbitrary: *server + ":" + *wgArbitrary,
		// Test 9 shares the HTTPS port (443) and selects the WireGuard-over-TLS
		// transport via the marker SNI, so it dials the same address the HTTPS
		// control plane uses.
		WGOverTLS: *server + ":443",
	}, *timeout, *idle, *reqTimeout, runOut)

	if tee != nil {
		tee.Close()
		os.Stdout = tee.console
	}
	if client.AnyFailed(results) {
		os.Exit(1)
	}
}

// debugTraceTemplate names the debug trace file written in -debug mode. The
// unix timestamp keeps the name unique per run and filesystem-safe on Windows
// (no spaces, colons, or slashes, which are illegal in file names).
const debugTraceTemplate = "network-test-debug-%d.txt"

// openDebugTrace creates the debug trace file in the current working
// directory. The relative path keeps the trace in the process's working
// directory regardless of platform, which is where a .bat-launched client on
// Windows runs.
func openDebugTrace() (*os.File, error) {
	name := fmt.Sprintf(debugTraceTemplate, time.Now().Unix())
	return os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
}

type stdoutTee struct {
	console    *os.File
	trace      *os.File
	pipeReader *os.File
	pipeWriter *os.File
	copied     sync.WaitGroup
}

func newStdoutTee(trace *os.File) (*stdoutTee, error) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}
	tee := &stdoutTee{console: os.Stdout, trace: trace, pipeReader: reader, pipeWriter: writer}
	tee.copied.Add(1)
	go func() {
		defer tee.copied.Done()
		_, _ = io.Copy(io.MultiWriter(tee.console, tee.trace), tee.pipeReader)
		_ = tee.pipeReader.Close()
	}()
	return tee, nil
}

func (t *stdoutTee) Close() {
	_ = t.pipeWriter.Close()
	t.copied.Wait()
	_ = t.trace.Close()
}
