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

## Status

Bootstrap. Tests 1-3 land first, then the WireGuard half (4-7).
