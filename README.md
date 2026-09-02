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

Runs tests 1-5 in order and prints one line per test as it completes, including
the source address the server observed and the round trip. Exit code is 1 if
any test failed, 0 otherwise. For tests 4 and 5 the client also speaks to the
server over the HTTPS control plane to exchange WireGuard keys, so those tests
need the HTTPS port reachable as well as the WireGuard UDP port.

```text
Client Network Connectivity Test
[PASS] HTTPS TCP/443    src=203.0.113.7:54780    rtt=87ms
[PASS] TCP/8443         src=203.0.113.7:39626    rtt=85ms
[PASS] UDP/60000        src=203.0.113.7:56769    rtt=88ms
[PASS] WireGuard UDP/51820 src=203.0.113.7:52101  rtt=91ms  handshake 91ms
[PASS] WireGuard UDP/443   src=203.0.113.7:49882  rtt=89ms  handshake 89ms

Conclusion:
WireGuard handshake works on both standard and non-standard ports. Direct WireGuard connectivity appears viable (tests 1-5).
```

## Status

Tests 1-5 done end to end. Remaining: test 6 (persistent UDP / NAT mapping
aging) and test 7 (bidirectional traffic through the tunnel).
