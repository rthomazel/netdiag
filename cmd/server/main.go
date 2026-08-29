package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/rthomazel/netdiag/internal/server"
)

func main() {
	var cfg server.Config
	flag.StringVar(&cfg.HTTPS, "https", ":443", "listen address for the HTTPS test")
	flag.StringVar(&cfg.TCP, "tcp", ":8443", "listen address for the arbitrary-TCP test")
	flag.StringVar(&cfg.UDP, "udp", ":60000", "listen address for the UDP test")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}
