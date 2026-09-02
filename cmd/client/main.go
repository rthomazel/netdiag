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
)

func main() {
	server := flag.String("server", "", "VPS host or IP (required)")
	timeout := flag.Duration("timeout", 5*time.Second, "per-test timeout")
	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "usage: netdiag-client -server <vps-ip> [-timeout 5s]")
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
	}, *timeout, os.Stdout)

	if client.AnyFailed(results) {
		os.Exit(1)
	}
}
