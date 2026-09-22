// WG handshake tests for the server: control-plane handlers, and a full
// in-process handshake over loopback UDP - the production shape minus the
// NAT (a passive server device, a client device that initiates via its
// keepalive, endpoint observation from the arriving packets).

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/rthomazel/netdiag/internal/protocol"
	"github.com/rthomazel/netdiag/internal/wgtest"
)

// startWG builds a WG backend on three ephemeral loopback UDP ports and
// returns it with the actual ports read back.
func startWG(t *testing.T) (*WG, int, int, int) {
	t.Helper()
	wg, err := NewWG("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewWG: %v", err)
	}
	t.Cleanup(wg.Close)
	p51820, err := wg.Port(protocol.TestWG51820)
	if err != nil {
		t.Fatalf("Port(wg51820): %v", err)
	}
	p443, err := wg.Port(protocol.TestWG443)
	if err != nil {
		t.Fatalf("Port(wg443): %v", err)
	}
	pArb, err := wg.Port(protocol.TestWGAbitrary)
	if err != nil {
		t.Fatalf("Port(wgarbitrary): %v", err)
	}
	return wg, p51820, p443, pArb
}

func TestWGKeysHandler(t *testing.T) {
	wg, _, _, _ := startWG(t)
	srv := httptest.NewTLSServer(httpsHandler(wg))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/wg")
	if err != nil {
		t.Fatalf("GET /wg: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var keys protocol.WGKeys
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		t.Fatalf("decode keys: %v", err)
	}
	if len(keys.WG51820) != 64 || len(keys.WG443) != 64 || len(keys.WGAbitrary) != 64 {
		t.Fatalf("bad key lengths: %d, %d, %d", len(keys.WG51820), len(keys.WG443), len(keys.WGAbitrary))
	}
	if keys.WG51820 != wg.Keys().WG51820 || keys.WG443 != wg.Keys().WG443 || keys.WGAbitrary != wg.Keys().WGAbitrary {
		t.Fatalf("served keys do not match the devices' public keys")
	}
}

func TestWGRegisterRejects(t *testing.T) {
	wg, _, _, _ := startWG(t)
	srv := httptest.NewTLSServer(httpsHandler(wg))
	defer srv.Close()

	validKey := "00"
	for i := 0; i < 31; i++ {
		validKey += "00"
	}
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"bad json", "{not json", http.StatusBadRequest},
		{"short key", `{"test":"wg51820","public_key":"abcd"}`, http.StatusBadRequest},
		{"unknown test", `{"test":"nope","public_key":"` + validKey + `"}`, http.StatusBadRequest},
	} {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/wg/register", bytes.NewReader([]byte(tc.body)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status = %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}

	resp, err := srv.Client().Get(srv.URL + "/wg/register")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /wg/register: status = %d, want 405", resp.StatusCode)
	}
}

func TestWGStatusUnknown(t *testing.T) {
	wg, _, _, _ := startWG(t)
	srv := httptest.NewTLSServer(httpsHandler(wg))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/wg/status/nope")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// TestWGHandshakeEndToEnd runs the real production exchange: the server device
// stays passive, the client device initiates via its keepalive, the handshake
// completes on both sides, and the server's Status reports the client's
// loopback source address (the NAT observation the report is built from).
func TestWGHandshakeEndToEnd(t *testing.T) {
	wg, p51820, _, _ := startWG(t)
	serverPub, _ := hex.DecodeString(wg.Keys().WG51820)

	dev, err := wgtest.NewClient(protocol.WGSubnet51820.Client, [32]byte(serverPub), protocol.WGSubnet51820.Server)
	if err != nil {
		t.Fatalf("client device: %v", err)
	}
	defer dev.Close()

	if err := wg.Register(protocol.TestWG51820, dev.PublicKey()); err != nil {
		t.Fatalf("register: %v", err)
	}

	endpoint := "127.0.0.1:" + strconv.Itoa(p51820)
	if err := dev.SetEndpointAndKeepalive([32]byte(serverPub), endpoint, 1); err != nil {
		t.Fatalf("set endpoint: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := dev.WaitHandshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	st, err := wg.Status(protocol.TestWG51820)
	if err != nil {
		t.Fatalf("server status: %v", err)
	}
	if st.LastHandshakeSec == 0 {
		t.Fatalf("server handshake not confirmed: %+v", st)
	}
	clientPort, _ := dev.ListenPort()
	want := "127.0.0.1:" + strconv.Itoa(clientPort)
	if st.Endpoint != want {
		t.Fatalf("server observed endpoint = %q, want %q (the client's source addr)", st.Endpoint, want)
	}
}

// TestWGSecondClientRun ensures a second, differently-keyed client run does
// not break the device: registration replaces the previous diagnostic peer
// (each client run generates fresh keys), so Status keeps working and the
// second handshake completes.
func TestWGSecondClientRun(t *testing.T) {
	wg, p51820, _, _ := startWG(t)
	serverPub, _ := hex.DecodeString(wg.Keys().WG51820)

	runClient := func() {
		dev, err := wgtest.NewClient(protocol.WGSubnet51820.Client, [32]byte(serverPub), protocol.WGSubnet51820.Server)
		if err != nil {
			t.Fatalf("client device: %v", err)
		}
		defer dev.Close()
		if err := wg.Register(protocol.TestWG51820, dev.PublicKey()); err != nil {
			t.Fatalf("register: %v", err)
		}
		endpoint := "127.0.0.1:" + strconv.Itoa(p51820)
		if err := dev.SetEndpointAndKeepalive([32]byte(serverPub), endpoint, 1); err != nil {
			t.Fatalf("set endpoint: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := dev.WaitHandshake(ctx); err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		st, err := wg.Status(protocol.TestWG51820)
		if err != nil {
			t.Fatalf("server status (would fail with accumulated peers): %v", err)
		}
		clientPort, _ := dev.ListenPort()
		if st.Endpoint != "127.0.0.1:"+strconv.Itoa(clientPort) {
			t.Fatalf("server observed %q, want the second client's source", st.Endpoint)
		}
	}

	runClient() // first run
	runClient() // second run: fresh key must replace the first peer
}

// TestWGDevicesIndependent ensures the three devices do not share state: a
// handshake on the arbitrary-port device must not leak onto the 51820 or 443
// devices.
func TestWGDevicesIndependent(t *testing.T) {
	wg, _, _, pArb := startWG(t)
	serverPub, _ := hex.DecodeString(wg.Keys().WGAbitrary)

	dev, err := wgtest.NewClient(protocol.WGSubnetArbitrary.Client, [32]byte(serverPub), protocol.WGSubnetArbitrary.Server)
	if err != nil {
		t.Fatalf("client device: %v", err)
	}
	defer dev.Close()
	if err := wg.Register(protocol.TestWGAbitrary, dev.PublicKey()); err != nil {
		t.Fatalf("register: %v", err)
	}

	endpoint := "127.0.0.1:" + strconv.Itoa(pArb)
	if err := dev.SetEndpointAndKeepalive([32]byte(serverPub), endpoint, 1); err != nil {
		t.Fatalf("set endpoint: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := dev.WaitHandshake(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if st, _ := wg.Status(protocol.TestWGAbitrary); st.LastHandshakeSec == 0 {
		t.Fatalf("arbitrary-port handshake not confirmed")
	}
	if st, _ := wg.Status(protocol.TestWG51820); st.Endpoint != "" {
		t.Fatalf("51820 device saw an endpoint %q; devices must be independent", st.Endpoint)
	}
	if st, _ := wg.Status(protocol.TestWG443); st.Endpoint != "" {
		t.Fatalf("443 device saw an endpoint %q; devices must be independent", st.Endpoint)
	}
}
