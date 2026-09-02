package client

import (
	"context"
	"testing"
	"time"

	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/wgtest"
)

// TestEchoPingNoEndpointTimesOut is the broken-tunnel failure path: a client
// device whose peer has no endpoint (no reachable tunnel) never gets an echo
// reply, so echoPing must return the context deadline rather than block.
func TestEchoPingNoEndpointTimesOut(t *testing.T) {
	subnet := protocol.WGSubnet51820
	dev, err := wgtest.NewClient(subnet.Client, [32]byte{1}, subnet.Server)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer dev.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := echoPing(ctx, dev, subnet); err == nil {
		t.Fatal("echoPing succeeded, want a timeout on a tunnel with no endpoint")
	}
}
