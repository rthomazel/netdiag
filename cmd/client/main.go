package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rthomazel/netdiag/internal/client"
	"github.com/rthomazel/netdiag/internal/protocol"
)

func main() {
	server := flag.String("server", "", "VPS host or IP (required)")
	timeout := flag.Duration("timeout", 5*time.Second, "per-test timeout")
	idle := flag.Duration("idle", protocol.DefaultPersistentWindow,
		"test 6 idle window (the persistent-NAT diagnostic; 60s is the deliberate default)")
	reqTimeout := flag.Duration("reqtimeout", 10*time.Second, "timeout per HTTPS control-plane request (key fetch, register, status poll)")
	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "usage: netdiag-client -server <vps-ip> [-timeout 5s] [-idle 1m]")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	results := client.Run(ctx, client.Target{
		HTTPS:   *server + ":443",
		TCP:     *server + ":8443",
		UDP:     *server + ":60000",
		WG51820: *server + ":51820",
		WG443:   *server + ":443",
	}, *timeout, *idle, *reqTimeout, os.Stdout)

	if client.AnyFailed(results) {
		os.Exit(1)
	}
}
