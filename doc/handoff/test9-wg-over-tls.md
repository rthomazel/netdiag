# Test 9 Handoff: WireGuard over TLS/TCP 443

## Purpose

Determine whether carrying WireGuard packets inside an ordinary-looking TLS connection
over TCP/443 can bypass WireGuard-specific filtering or DPI. This is a diagnostic
transport test, not the final production VPN.

We already know (tests 1-8) that:
- Tests 1-3 pass (HTTPS, arbitrary TCP, arbitrary UDP)
- Tests 4-7 time out (standard WireGuard over UDP)
- Test 8 distinguishes UDP port filtering from WireGuard DPI (still running)

Test 9 probes whether TLS encapsulation hides WireGuard's packet signature.

---

## Design Summary

### Transport

- TLS over TCP/443. Not QUIC or DTLS -- TCP head-of-line blocking is acceptable for a
  diagnostic test.
- Custom `conn.Bind` implementing the WireGuard bind interface, wrapping a `*tls.Conn`.
- Single connection, bidirectional. Go allows concurrent read/write on one `tls.Conn`,
  so the client's outbound handshake packets and the server's replies both flow over the
  same connection. No second socket needed.
- Same passive-device model as tests 4-8: server learns the client's source from
  arriving packets.

### Wire Format

Each WireGuard packet is framed with a 4-byte big-endian length prefix inside the TLS stream:

```
+----------------------+----------------------+
| 4-byte BE length     | WireGuard packet     |
+----------------------+----------------------+
```

The WireGuard packet signature (01 00 00 00 ...) is inside TLS application data, hidden
from DPI. The entire framing prefix and payload are encrypted once written through TLS.

### SNI Routing (the fork decision)

The client uses a distinctive-but-HTTPS-shaped marker SNI for the WireGuard-over-TLS
connection. The server routes by SNI after TLS termination:

- marker SNI -> a 4th passive WireGuard device (test 9)
- otherwise -> the existing HTTPS control plane mux

Caveat: the marker SNI remains visible in the TLS ClientHello. This test does not attempt
Reality-style TLS camouflage or JA3/JA4 evasion. The goal is simply to test whether
WireGuard can blend into 443/HTTPS traffic while retaining a server-side way to
distinguish the diagnostic transport.

Choose a plausible HTTPS-shaped hostname. German is preferred (VPS is in Germany), but
any distinctive SNI works. This must be a stable shared marker known to both client
and server.

---

## Server Changes

File: /projects/netdiag/internal/server/server.go

### 1. Single shared TCP listener on :443

Currently the HTTPS listener uses `tls.Listen(...)` directly. For test 9, the HTTPS mux
and the WireGuard-over-TLS transport must share ONE TCP listener on `cfg.HTTPS` (which
defaults to :443). The current `tls.Listen` call must become a plain
`net.Listen("tcp", ...)`.

Then wrap that listener in a TLS server that:
- Accepts each connection
- Performs the TLS handshake
- Inspects the SNI from `tls.ConnectionState().ServerName`
- Routes:
  - marker SNI -> handle as WireGuard-over-TLS (new code below)
  - otherwise -> hand off to the existing HTTPS `http.Server` handler

### 2. Add a 4th WireGuard device

File: /projects/netdiag/internal/server/wg.go

- Extend `NewWG` to build a 4th passive device (like the existing 3).
- Add it to the `devs` map under a new test name constant.
- Update `Keys()` to return its public key.
- Update `Known()`, `Register()`, `Status()`, `Port()` to handle it.
- Give it its own tunnel subnet (see protocol section below).

### 3. WireGuard-over-TLS handler

When the marker SNI is detected, handle the connection as follows:

The server-side device needs a `conn.Bind` too, since it is passive and must (a) receive
the client's framed WireGuard packets and process the handshake, learning the client's
endpoint, and (b) send reply packets back out over the same TLS connection. Mirror the
client's bind in reverse:

- Read framed packets from the `*tls.Conn` (exact reads: 4-byte length, then N payload).
- Inject the raw WireGuard bytes into the device's receive path. This is the tricky part:
  investigate `internal/wgtest/device.go` for how the device's bind is structured and
  whether there's an injection point. You likely need a minimal server-side TLS-backed
  `conn.Bind` wrapper that the passive device uses, then feed packets by invoking the
  bind's receive path (not by calling `Write` on some network socket directly).
- The device generates reply packets; the server-side bind's `Send` writes them back
  into the TLS connection, prefixed with their 4-byte length.

The handshake is triggered by the client's persistent keepalive. After the handshake
completes, the connection can close -- test 9 is a handshake test, not a persistent
tunnel test. Success = server observes a client endpoint AND confirms the handshake.

### 4. Shutdown

Ensure the shared listener, TLS server, and 4th device are cleaned up on ctx.Done()
alongside the existing listeners, per the pattern in `Serve()`.

---

## Client Changes

Files:
- /projects/netdiag/internal/client/client.go (wiring)
- /projects/netdiag/internal/client/wg.go (key fetch, register, status poll patterns)
- New file: internal/client/wgtls.go (the custom bind + test runner)

### 1. Add target for test 9

The client dials `t.WGOverTLS` = `<vps>:443` with a special SNI. Reuses the HTTPS port
but with a different SNI. Add to the `Target` struct.

### 2. Register on the TLS test

Fetch 4 keys (now includes the test 9 device) and register the client's device key
against the new test name.

### 3. Custom `conn.Bind` (internal/client/wgtls.go)

Implement `golang.zx2c4.com/wireguard/conn.Bind` wrapping a `*tls.Conn`.

Required methods:
- Open() error
- Send(bs [][]byte) error
- ReceiveFunc(func(int, []byte, int))
- ParseEndpoint(endpoint []byte) (conn.Endpoint, error)
- BatchSize() int
- SetMark(mark uint32) error
- Close() error

#### Send (client -> server)

For each packet, frame it with a 4-byte big-endian length prefix, concatenate
[length-prefix][packet] into one buffer, and issue a single `tls.Conn.Write` so the
frame boundary is preserved (tls.Conn.Write is not guaranteed atomic across multiple
calls). Reject packets larger than the max transport message size.

#### Receive (server -> client)

Install a goroutine that loops:
1. Read exactly 4 bytes -> decode big-endian length.
2. Validate against the safe maximum before allocating.
3. Read exactly that many payload bytes.
4. Deliver the payload to the WireGuard device via the installed callback.

CRITICAL: TLS reads do not preserve message boundaries. One tls.Conn.Read may return a
partial frame, a full frame, or multiple coalesced frames. Never assume one read = one
packet. Always do exact reads as above.

Also support concurrent Read and Write on the one tls.Conn (the device reads replies
while the client writes handshakes). Do not serialize them.

#### Open

Dial TCP/443, wrap in `tls.Client` with `InsecureSkipVerify: true` and
`ServerName: markerSNI`. Call `HandshakeContext` before returning success.

#### BatchSize

Return `conn.IdealBatchSize` (typically 256).

#### ParseEndpoint

Return a minimal/unspecified endpoint. Inspect the existing UDP bind in
`internal/wgtest/device.go` for the pattern, or return an unspecifiedEndpoint from the
wireguard conn package if available.

#### SetMark

No-op (or store the mark). Return nil.

#### Close

Close the underlying tls.Conn.

### 4. Run the handshake over TLS

Construct the WireGuard device using this tlsBind instead of the UDP bind. Inspect
`internal/wgtest/device.go` carefully: `wgtest.NewClient` may hardcode a UDP bind, in
which case you must build the device directly with the custom bind. Then:
- Register the device key
- Point the peer at the server (the bind ignores the endpoint anyway)
- Arm the keepalive to trigger the handshake
- Poll the server status endpoint over HTTPS (reuse the pattern from wg.go)
- Report PASS if the server observes a client endpoint AND confirms the handshake

Result line: `[PASS] WireGuard TLS/443 src=<observed>  rtt=<dur>`

---

## Protocol Changes

File: /projects/netdiag/internal/protocol/protocol.go

- Add a new test name constant (e.g. `TestWGOverTLS`).
- Add a 4th tunnel subnet.
- Add a `WgOverTLSPacketMaxSize` constant (~1600 bytes; WireGuard transport messages are
  bounded, so this comfortably exceeds device.MaxMessageSize).

### Tunnel Subnets

Existing:
- WGSubnet51820: Server 10.66.0.1, Client 10.66.0.2
- WGSubnet443: Server 10.67.0.1, Client 10.67.0.2
- WGSubnetArbitrary: Server 10.68.0.1, Client 10.68.0.3

Add a 4th:
- WGSubnetTLS: Server 10.69.0.1, Client 10.69.0.2

Each test gets its own independent subnet so handshakes never leak across tests.

---

## Key Files to Read Before Implementing

1. internal/wgtest/device.go -- device constructor, how conn.Bind is passed to the
   WireGuard device, how packets flow in/out. THE most important file here.
2. internal/server/wg.go -- passive device model, how devices learn client endpoints,
   how to add a 4th device.
3. /root/go/pkg/mod/golang.zx2c4.com/wireguard@*/conn/bind.go -- the conn.Bind interface
   definition (find the exact path with ls).
4. internal/client/wg.go -- how wgTest sets up the client device and polls status.
5. internal/client/client.go -- how tests are wired and reported.
6. server/server.go -- the shared-listener refactor.

---

## Testing

The test should:
1. Fetch 4 keys (including the new test 9 device)
2. Register the client's device key against the new test
3. Dial TCP/443 with the marker SNI, establish TLS
4. Run the WireGuard handshake over the TLS connection
5. Poll the server status endpoint over HTTPS
6. Report PASS if the server observes a client endpoint AND confirms the handshake

`go vet ./...` and `go test ./...` must still pass. No regression to tests 1-8.

---

## Potential Pitfalls

1. TLS frame boundaries. Exact reads only (4-byte length, then N payload). Do not assume
   one tls.Conn.Read = one WireGuard packet.
2. Concurrent read/write. tls.Conn supports it; ensure the bind does not serialize the
   client's outbound handshakes against the server's replies.
3. Server-side packet injection. Feeding received WireGuard packets into the passive
   device is the trickiest part. Investigate internal/wgtest/device.go for a way to
   inject raw packets or a server-side bind wrapper.
4. SNI visibility. The marker SNI is in the plaintext ClientHello. No Reality/JA3
   evasion. If DPI flags the SNI specifically, that's still a valid diagnostic result.
5. Device construction. NewClient may hardcode the UDP bind; you may need to construct
   the device directly with the custom bind.
6. Keepalive triggering. Handshake is triggered by the client's persistent keepalive
   with no keypair. Arm the keepalive only after the endpoint is set (see the note in
   internal/wgtest/device.go: having both sides initiate at once conflicts the index
   tables).
7. Cleanup. The tlsBind lifecycle must match the device lifecycle.

---

## Scope

Test 9 only. Does not modify tests 1-8. Adds:
- One new server-side passive device
- One new client-side test
- Shares the single TCP/443 listener between HTTPS and WireGuard-over-TLS

No QUIC, no DTLS, no TLS camouflage beyond the marker SNI.

The result informs whether TLS encapsulation can hide WireGuard's packet signature from
DPI. Whether it becomes the production transport is a separate decision.
