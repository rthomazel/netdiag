package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rthomazel/netdiag/internal/protocol"
)

func TestHTTPSListener(t *testing.T) {
	// nil WG: the probe route must behave exactly as before tests 4 and 5.
	srv := httptest.NewTLSServer(httpsHandler(nil))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/probe")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var res protocol.Result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if res.Name != protocol.TestHTTPS443 || res.Status != protocol.StatusPass {
		t.Fatalf("result = %+v", res)
	}
	host, _, err := net.SplitHostPort(res.Src)
	if err != nil {
		t.Fatalf("src %q is not host:port: %v", res.Src, err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("observed host = %q, want 127.0.0.1", host)
	}
}

func TestTCPListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go acceptTCP(context.Background(), ln)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	const seq, ts = 7, 99
	if _, err := conn.Write(protocol.EncodeACKRequest(seq, ts)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, protocol.RespSize)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	gotSeq, gotTS, ip, port, ok := protocol.DecodeACKResponse(buf)
	if !ok {
		t.Fatal("bad response frame")
	}
	wantPort := uint16(conn.LocalAddr().(*net.TCPAddr).Port)
	if gotSeq != seq || gotTS != ts || !ip.Equal(net.ParseIP("127.0.0.1")) || port != wantPort {
		t.Fatalf("got (%d, %d, %s, %d), want (%d, %d, 127.0.0.1, %d)", gotSeq, gotTS, ip, port, seq, ts, wantPort)
	}
}

func TestUDPListener(t *testing.T) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	go readUDP(context.Background(), uc)

	cc, err := net.Dial("udp", uc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	const seq, ts = 3, 42
	if _, err := cc.Write(protocol.EncodeACKRequest(seq, ts)); err != nil {
		t.Fatalf("write: %v", err)
	}
	cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, protocol.RespSize)
	if _, err := cc.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	gotSeq, gotTS, ip, port, ok := protocol.DecodeACKResponse(buf)
	if !ok {
		t.Fatal("bad response frame")
	}
	wantPort := uint16(cc.LocalAddr().(*net.UDPAddr).Port)
	if gotSeq != seq || gotTS != ts || !ip.Equal(net.ParseIP("127.0.0.1")) || port != wantPort {
		t.Fatalf("got (%d, %d, %s, %d), want (%d, %d, 127.0.0.1, %d)", gotSeq, gotTS, ip, port, seq, ts, wantPort)
	}
}

func TestUDPRejectsGarbage(t *testing.T) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	go readUDP(context.Background(), uc)

	cc, err := net.Dial("udp", uc.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	if _, err := cc.Write(make([]byte, protocol.ReqSize)); err != nil { // zero magic
		t.Fatalf("write: %v", err)
	}
	cc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, protocol.RespSize)
	if _, err := cc.Read(buf); err == nil {
		t.Fatal("garbage datagram was acknowledged")
	}
}
