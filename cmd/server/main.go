package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/rthomazel/netdiag/internal/server"
)

// Listen address env vars, with the defaults as their fallbacks.
// NETDIAG_ prefix so it's obvious which daemon they belong to.
const (
	envHTTPS = "NETDIAG_HTTPS"
	envTCP   = "NETDIAG_TCP"
	envUDP   = "NETDIAG_UDP"
)

func main() {
	cfg := server.Config{
		HTTPS: envOr(envHTTPS, ":443"),
		TCP:   envOr(envTCP, ":8443"),
		UDP:   envOr(envUDP, ":60000"),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("netdiag server: https=%s tcp=%s udp=%s", cfg.HTTPS, cfg.TCP, cfg.UDP)
	if err := server.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
