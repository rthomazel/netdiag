# WireGuard in the harness: overview and learnings

How the WireGuard handshake tests (4 and 5) work, and the non-obvious
behaviors we had to run into (and fix) to make them work. The wireguard-go
API docs do not cover any of this; every item in [Learnings](#learnings--verified-by-running)
was verified by running devices over real UDP loopback before being trusted.

## High-level overview

The goal of tests 4 and 5 is to find out whether the client's network lets a
*real WireGuard handshake* complete: to UDP/51820 (test 4) and to UDP/443
(test 5, where UDP :443 coexists with the TCP :443 HTTPS listener — different
protocols, no conflict). Not "can UDP reach this port" (that is test 3), but
"can the protocol pass". A network that fingerprint-blocks WireGuard will pass
test 3 and drop test 4; a network that allows only standard ports will pass
5 but drop 4.

### File map

| File | Role |
|---|---|
| `internal/wgtest/device.go` | the in-memory WireGuard device (used by both sides) |
| `internal/server/wg.go` | the two passive server devices + the `/wg*` control-plane endpoints |
| `internal/client/wg.go` | fetch keys, register, initiate, confirm |
| `internal/protocol/protocol.go` | `WGKeys`, `Subnet`, test names |

### Passive server, active client

Both sides run a real userspace WireGuard device in-process, but the roles
are asymmetric:

- **The server is passive.** It configures no client endpoint and never
  initiates. It learns the client's source address from the arriving
  handshake packets — and that observed endpoint *is* the NAT info the report
  shows. The WireGuard device records the source IP:port of incoming packets
  automatically (`endpoint=` in the uAPI dump), so the protocol itself is the
  probe; no packet sniffing is needed.
- **The client is active** and is the only side that initiates.

### No TUN, no kernel module, no cgo

The device runs entirely in memory, but its network I/O is real:

- `tuntest.ChannelTUN` is a fake TUN: an in-memory channel pair
  (`Inbound`/`Outbound`) standing in for a kernel TUN file descriptor. We
  never need real interface traffic — the handshake test only needs to observe
  that the handshake completed; test 7 (later) will push ping packets through
  the same channels.
- `conn.NewStdNetBind` does the real networking: an actual UDP socket on the
  real network path. That is what makes the test a test.
- Result: no TUN device, no kernel module, no privileges, no cgo. The Windows
  client cross-builds with `CGO_ENABLED=0` (CI verifies this).
- Keys are generated in-process with `curve25519.ScalarBaseMult` (x/crypto):
  32 random bytes of private key, public key derived.

### Key exchange over the HTTPS control plane

A handshake needs each side's public key. There is no pre-shared config: the
existing HTTPS control plane (the same listener as test 1) carries the
exchange. The client generates a fresh keypair on every run.

| Route | Direction | Purpose |
|---|---|---|
| `GET /wg` | client → server | the server's public keys for both test devices |
| `POST /wg/register` | client → server | the client's device key → server adds it as the passive peer |
| `GET /wg/status/<test>` | client → server | the server's view: observed endpoint, last handshake time, byte counters |

### Handshake flow, per test

**Client** (one deadline for the whole flow — the handshake wait and the
server-side confirmation share a single timeout context):

1. Fetch the server's public keys (`GET /wg`).
2. Build the in-memory device: tunnel IP 10.66.0.2 (test 4) / 10.67.0.2
   (test 5), ephemeral UDP port, peer pre-configured = the server
   (10.66.0.1 / 10.67.0.1, `allowed_ip` /32). **No keepalive armed yet.**
3. Register the device's public key (`POST /wg/register`) so the server has
   a peer to talk to.
4. In one `IpcSet`: point the peer at `server:port` **and** arm a 1s
   persistent keepalive. This call starts the handshake (see Learning 1).
5. Poll `IpcGet` locally until `last_handshake_time_sec > 0` → handshake
   completed; the elapsed time is the test's rtt.
6. Confirm on the **server**: poll `GET /wg/status/<test>` until
   `last_handshake_time_sec > 0` **and** `endpoint != ""`. The endpoint is
   the report's `src=`. Both conditions are required (see Learning 6).

If step 1 fails (control plane unreachable), the test is reported as a fail
with detail `untestable: ...` — the report must still render, and a reader
should not mistake "can't reach the HTTPS port" for "WireGuard is blocked".

**Server** (at startup): two devices, each with its own keypair, listening on
its test port, no peers. When a client registers, `ReplacePeer` makes that
client the device's *only* peer: `allowed_ip` = the client's tunnel IP, no
endpoint. That is all the server ever does; the device does the rest.

### The protocol in one paragraph

A WireGuard handshake is a 3-message exchange (1: client→server initiates,
2: server→client, 3: client→server completes), after which traffic is
encrypted under a fresh keypair re-keyed every ~2 minutes. Persistent
keepalives are tiny encrypted packets sent on an interval; they keep NAT
mappings alive and let each side detect a dead peer. The client arms a 1s
keepalive so the mapping stays warm through the whole run and the device
re-initiates quickly after each re-key.

## Learnings — verified by running

### 1. The keepalive is the handshake initiation

There is no explicit "initiate handshake" call. Setting
`persistent_keepalive_interval` from 0 schedules an immediate keepalive, and
a keepalive sent **while no handshake keypair exists** is converted into a
handshake initiation (message 1) by the device (`SendStagedPackets`). So the
`IpcSet(endpoint + persistent_keepalive_interval)` call *is* the moment the
handshake starts, and it must be a single call:

- arming the keepalive in a separate `IpcSet` *before* the endpoint makes the
  immediate keepalive fire with no endpoint — it cannot be sent, and the
  real initiation is deferred to the 5s retransmit timer. Handshakes took
  5s+ instead of ~50ms until this was fixed.
- `Peer.Start()` alone does not arm anything; the keepalive is the mechanism.

### 2. Only one side may initiate

If both devices arm keepalives and initiate at the same time, the handshake
**never completes**: each side's initiation conflicts the other's index
tables and the exchange never converges. Our topology is client-initiated,
server-passive. (After a handshake has completed, keepalives from both sides
coexist fine — this is about the initial handshake only.)

### 3. `IpcGet` is the full oracle

The uAPI dump gives everything the report needs, passively:

- `endpoint=` — the source address last *observed* from the peer. Updated
  automatically from received packets. This is the NAT observation.
- `last_handshake_time_sec` — unix timestamp of the last completed handshake;
  0 means none ever.
- `tx_bytes` / `rx_bytes` — per-peer byte counters.
- `listen_port=` — the actual port (you must read it back when you request 0
  for an ephemeral bind).

### 4. The server stays fully passive

The server must never set the client's endpoint. If it did, it would also
initiate/retransmit (violating Learning 2) and would answer toward the
configured address instead of wherever the packet actually came from. With no
endpoint configured, the device answers to the observed source — exactly
what the diagnostic needs. (`ReplacePeer` deliberately takes no endpoint.)

### 5. Registration must replace, not accumulate

Each client run generates a fresh keypair. If `Register` *adds* a peer, a
second run leaves two peers on the device: `Status` refuses to guess which
peer's counters to report, and the test is broken until the server restarts.
`replace_peers=true` makes a new run supersede the previous one.

### 6. An endpoint is not proof of a handshake

The server records `endpoint=` from the client's *first* handshake packet
(message 1), **before** the exchange completes. A network that delivers
outbound but drops the server's replies would show an observed endpoint with
no handshake completion. The pass condition is therefore
`last_handshake_time_sec > 0` **and** `endpoint != ""`, and the *server's*
status is the source of truth for pass/fail — the client finishing its local
poll is the weak signal, the server confirming is the strong one.

### 7. Fake-TUN mechanics (basis for test 7)

- `ChannelTUN` routes by packet **destination**: to ping X → Y, inject a
  packet addressed to Y into `X.TUN.Outbound` and read it on `Y.TUN.Inbound`.
- A 32-byte ping is 16-byte aligned → no MTU padding; the delivered TUN
  payload is byte-identical to what was injected (encryption overhead lives
  on the UDP wire, not in the TUN payload).
- Keepalives advance `tx_bytes` (client) / `rx_bytes` (server) while
  `last_handshake_time_sec` stays stable — the measurement basis for test 6:
  bytes moving with the handshake time frozen means keepalives are still
  getting through.

### 8. Versions and the Windows build

- Pinned `golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446`
  (userspace implementation). The wintun TUN driver is *not* used —
  `tuntest.ChannelTUN` is pure Go — so nothing cgo pulls in:
  `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build` works, and CI
  cross-builds the client that way.
- `tuntest` is a `//go:build`-free test helper package that ships inside the
  module, so using it in production code does not require test dependencies.

## Tuning knobs (chosen values, and why)

- **1s keepalive** — short enough to keep NAT mappings warm during test 6's
  60s idle and to re-initiate fast after a re-key; not noisy.
- **Ephemeral client port** — the client's source port is arbitrary anyway;
  only the server ports are fixed to the test ports.
- **Separate subnets per test** (10.66.0.0/24, 10.67.0.0/24) — the two
  devices are independent; a 443 handshake must not appear on the 51820
  device (regressed in the tests).
- **50ms status polls** — handshakes complete in ~50ms locally; polling
  faster keeps the measured rtt honest.
- **One deadline per test** — handshake wait + server confirmation share a
  single timeout, so a slow network cannot stack two full timeouts.

## Open (next PRs)

- **Test 6 — NAT mapping aging**: 60s idle with the 1s keepalive
  (PersistentKeepalive), then resend; compare observed endpoint + tx/rx
  bytes to see whether the client's NAT aged the mapping out from under us.
- **Test 7 — bidirectional tunnel traffic**: pings through the ChannelTUN in
  both directions; the server needs an echo responder on `TUN.Inbound`.
