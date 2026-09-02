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
	envHTTPS   = "NETDIAG_HTTPS"
	envTCP     = "NETDIAG_TCP"
	envUDP     = "NETDIAG_UDP"
	envWG51820 = "NETDIAG_WG_51820"
	envWG443   = "NETDIAG_WG_443"
)

func main() {
	cfg := server.Config{
		HTTPS:   envOr(envHTTPS, ":443"),
		TCP:     envOr(envTCP, ":8443"),
		UDP:     envOr(envUDP, ":60000"),
		WG51820: envOr(envWG51820, ":51820"),
		WG443:   envOr(envWG443, ":443"),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("netdiag server: https=%s tcp=%s udp=%s wg51820=%s wg443=%s",
		cfg.HTTPS, cfg.TCP, cfg.UDP, cfg.WG51820, cfg.WG443)
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
