# netdiag

Network connectivity diagnostic harness. A Go client/server pair that characterizes
what a network permits before we build a WireGuard VPN on top of it.

- `server` runs on a VPS with a fixed public IP. It is the oracle: it logs the source
  IP:port it observes for every test and hands it back to the client over the control
  plane, so the report shows the public address the client arrives from.
- `client` runs on the machine inside the network under test (Windows first).

Plan: rthomazel/interface `doc/ideas/inbox/netdiag.md` (idea [31]).

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
go run ./cmd/server            # binds :443, :8443, :60000
```

| Env var         | Default  | Serves                    |
| --------------- | -------- | ------------------------- |
| `NETDIAG_HTTPS` | `:443`   | test 1 (self-signed TLS)  |
| `NETDIAG_TCP`   | `:8443`  | test 2 (ACK exchange)     |
| `NETDIAG_UDP`   | `:60000` | test 3 (ACK datagrams)    |

The destination address identifies the test; the server logs the source IP:port
it observes for every inbound connection/datagram — that log is the NAT report.

### Client (inside the network under test)

```sh
go run ./cmd/client -server <vps-ip>
```

Runs tests 1-3 in order and prints one line per test as it completes, including
the source address the server observed. (Lands in the next PR.)

## Status

Tests 1-3 server side done; client lands next, then the WireGuard half (4-7).
