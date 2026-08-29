package protocol

import (
	"math"
	"net"
	"testing"
)

func TestACKRequestRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		seq uint16
		ts  int64
	}{
		{0, 0},
		{1, 1_700_000_000_123_456_789},
		{0xFFFF, math.MaxInt64},
	} {
		frame := EncodeACKRequest(tc.seq, tc.ts)
		if len(frame) != ReqSize {
			t.Fatalf("request size = %d, want %d", len(frame), ReqSize)
		}
		seq, ts, ok := DecodeACKRequest(frame)
		if !ok {
			t.Fatalf("decode failed for seq=%d ts=%d", tc.seq, tc.ts)
		}
		if seq != tc.seq || ts != tc.ts {
			t.Fatalf("round trip = (%d, %d), want (%d, %d)", seq, ts, tc.seq, tc.ts)
		}
	}
}

func TestACKResponseRoundTrip(t *testing.T) {
	cases := []net.IP{
		net.ParseIP("203.0.113.7"), // IPv4
		net.ParseIP("2001:db8::1"), // IPv6
		net.ParseIP("::ffff:192.0.2.9").To16(),
	}
	for _, src := range cases {
		frame := EncodeACKResponse(42, 123, src, 54321)
		if len(frame) != RespSize {
			t.Fatalf("response size = %d, want %d", len(frame), RespSize)
		}
		seq, ts, gotSrc, port, ok := DecodeACKResponse(frame)
		if !ok {
			t.Fatalf("decode failed for src=%s", src)
		}
		if seq != 42 || ts != 123 || port != 54321 {
			t.Fatalf("round trip = (%d, %d, %d), want (42, 123, 54321)", seq, ts, port)
		}
		if !gotSrc.Equal(src.To16()) {
			t.Fatalf("src = %s, want %s", gotSrc, src)
		}
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	req := EncodeACKRequest(1, 2)
	resp := EncodeACKResponse(1, 2, net.ParseIP("198.51.100.1"), 9999)

	// Corrupt one byte in the body -> checksum mismatch.
	badReq := append([]byte(nil), req...)
	badReq[5] ^= 0xFF
	if _, _, ok := DecodeACKRequest(badReq); ok {
		t.Fatal("corrupted request accepted")
	}

	badResp := append([]byte(nil), resp...)
	badResp[15] ^= 0xFF
	if _, _, _, _, ok := DecodeACKResponse(badResp); ok {
		t.Fatal("corrupted response accepted")
	}

	// Wrong length.
	if _, _, ok := DecodeACKRequest(req[:10]); ok {
		t.Fatal("short request accepted")
	}
	if _, _, _, _, ok := DecodeACKResponse(resp[:29]); ok {
		t.Fatal("short response accepted")
	}

	// Wrong magic.
	badMagic := append([]byte(nil), req...)
	badMagic[0] = 0x00
	if _, _, ok := DecodeACKRequest(badMagic); ok {
		t.Fatal("wrong-magic request accepted")
	}
}
