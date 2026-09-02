# netdiag

Network connectivity diagnostic harness. A Go client/server pair that characterizes
what a network permits before we build a WireGuard VPN on top of it.

- `server` runs on a VPS with a fixed public IP. It is the oracle: it logs the source
  IP:port it observes for every test and hands it back to the client over the control
  plane, so the report shows the public address the client arrives from.
- `client` runs on the machine inside the network under test (Windows first).

Plan: rthomazel/interface `doc/ideas/inbox/netdiag.md` (idea [31]).

The WireGuard tests (4-5) and their non-obvious behaviors are documented in
[`doc/wireguard.md`](doc/wireguard.md).

## Test suite (in order)

1. HTTPS/TCP 443 — baseline: normal outbound works
2. TCP arbitrary port (8443) — is TCP restricted to standard ports?
3. UDP arbitrary port — application-level ACK from server, not send-and-hope
4. WireGuard handshake on UDP/51820 — the protocol-specific question
5. WireGuard handshake on UDP/443 — port filtering vs WireGuard fingerprinting
6. Persistent UDP — hold tunnel, idle, resend; with PersistentKeepalive
7. Bidirectional traffic through the tunnel

## Running

### Server (VPS)

```sh
go run ./cmd/server            # binds :443, :8443, :60000, :51820 (UDP), :443 (UDP)
```

| Env var           | Default  | Serves                    |
| ----------------- | -------- | ------------------------- |
| `NETDIAG_HTTPS`   | `:443`   | test 1 (self-signed TLS)  |
| `NETDIAG_TCP`     | `:8443`  | test 2 (ACK exchange)     |
| `NETDIAG_UDP`     | `:60000` | test 3 (ACK datagrams)    |
| `NETDIAG_WG_51820`| `:51820` | test 4 (WireGuard, UDP)   |
| `NETDIAG_WG_443`  | `:443`   | test 5 (WireGuard, UDP)   |

The destination address identifies the test; the server logs the source IP:port
it observes for every inbound connection/datagram — that log is the NAT report.

Tests 4 and 5 run a real WireGuard device in-process (fake TUN over a real UDP
bind, no kernel module, no cgo). The server-side device is passive: it generates
its own keypair, exposes the public key over the HTTPS control plane
(`GET /wg`), and learns the client's source address from the handshake packets
that arrive. The client registers its own device key (`POST /wg/register`) and
starts the handshake; `GET /wg/status/<test>` reports the observed endpoint and
handshake time. TCP/443 and UDP/443 coexist on the same port, which is exactly
the production condition test 5 exists to probe.

### Client (inside the network under test)

```sh
go run ./cmd/client -server <vps-ip>
```

Runs tests 1-7 in order and prints one line per test as it completes, including
the source address the server observed and the round trip. Exit code is 1 if
any test failed, 0 otherwise. For tests 4-7 the client also speaks to the
server over the HTTPS control plane to exchange WireGuard keys, so those tests
need the HTTPS port reachable as well as the WireGuard UDP port.

`-timeout` is the per-test deadline (default 5s). `-idle` is test 6's idle
window — the length of the persistent-NAT diagnostic, defaulted to 60s. Test 6
is deliberately slow because the idle window is the thing being measured; pass
a shorter `-idle` for a quick local run.

```text
Client Network Connectivity Test
[PASS] HTTPS TCP/443    src=203.0.113.7:54780    rtt=87ms
[PASS] TCP/8443         src=203.0.113.7:39626    rtt=85ms
[PASS] UDP/60000        src=203.0.113.7:56769    rtt=88ms
[PASS] WireGuard UDP/51820 src=203.0.113.7:52101  rtt=91ms  handshake 91ms
[PASS] WireGuard UDP/443   src=203.0.113.7:49882  rtt=89ms  handshake 89ms
[PASS] WireGuard persistent  src=203.0.113.7:52101  rtt=1m0s  kept alive 1m0s (rx 120 -> 121 bytes)
[PASS] WireGuard bidir   src=203.0.113.7:52101  rtt=2ms  5 pings each direction

Conclusion:
WireGuard works end to end: handshake on both standard and non-standard ports, NAT mapping holds across the idle window, and traffic flows in both directions (tests 1-7). Direct WireGuard connectivity appears viable.
```

## Status

All 7 tests done end to end. Tests 1-5 verify the baseline protocols and the
WireGuard handshake on standard and non-standard ports. Test 6 (persistent)
verifies the NAT mapping survives the 60s idle by asserting keepalives still
flow and the observed endpoint is unchanged, then resends traffic through the
tunnel. Test 7 (bidir) pushes pings through the tunnel in both directions,
each answered by the server's echo responder.
