# Deploying netdiag

Two halves: a pure-Go **client** binary you run on the machine inside the
network under test (Windows first), and a **server** that runs on the LGA VPS
(Hetzner) as the oracle. The server observes the source IP:port every test
arrives from and hands it back over the HTTPS control plane — that log IS the
NAT report, which is why the server must bind the VPS public IP directly
(host networking, not Docker bridge NAT).

```
┌─────────────────────────┐        tests 1-7         ┌──────────────────────────┐
│ Windows client          │  ───────────────────────▶  │ LGA VPS (Hetzner)       │
│ netdiag-client.exe      │   TCP 443/8443,          │ netdiag-server          │
│ (in the network under   │   UDP 60000/51820/443    │ docker, host networking │
│  test)                  │  ◀───────────────────────  │ 5 listeners             │
└─────────────────────────┘   control plane + ACKs    └──────────────────────────┘
```

## Client: build for Windows

The client is pure Go — no cgo, no wintun, no kernel module — so it
cross-compiles from anywhere (Linux, macOS, or Windows itself). It builds with
`CGO_ENABLED=0 GOOS=windows GOARCH=amd64`, which CI does on every push; the
commands below reproduce it locally.

```sh
git clone git@github.com:rthomazel/netdiag.git
cd netdiag
go mod download

# Cross-build (from any OS) — or run the same without GOOS/CGO on a Windows
# box. Output: netdiag-client.exe
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o netdiag-client.exe ./cmd/client
```

The result is a single self-contained `.exe` — no runtime to install on the
Windows machine, no admin privileges, no service. Copy it next to wherever you
want to run the test (the machine whose network you are diagnosing).

## Client: run the test on Windows

From a normal PowerShell/CMD prompt on that machine, point at the VPS IP or
hostname. No ports to specify — the client derives all five destinations
(`:443`, `:8443`, `:60000`, `:51820`, and `:443/udp`) from the one address.

```sh
netdiag-client.exe -server <vps-ip>
```

Flags:

| Flag        | Default | Meaning                                                        |
| ----------- | ------- | -------------------------------------------------------------- |
| `-server`   | (req.)  | VPS host or IP the tests dial                                   |
| `-timeout`  | `5s`    | per-test deadline (tests 1-5)                                   |
| `-idle`     | `1m`    | test 6's idle window — the length of the persistent-NAT diagnostic |

A full run takes roughly a minute, dominated by test 6's deliberate 60-second
idle window (that length is the diagnostic — do not shorten it for a real run).
For a quick "is it even reachable" check use a short idle:

```sh
netdiag-client.exe -server <vps-ip> -idle 5s
```

Each test prints its line the moment it completes, with the `src=` the server
observed (the public address this machine arrives from) and the round trip.
Exit code is `0` if all 7 pass, `1` otherwise, `2` on usage error. Ctrl-C
stops it cleanly.

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
WireGuard works end to end: handshake on both standard and non-standard ports,
NAT mapping holds across the idle window, and traffic flows in both
directions (tests 1-7). Direct WireGuard connectivity appears viable.
```

Note on TLS: the client uses `InsecureSkipVerify`. The test measures
reachability and NAT behavior, not the certificate, so the server's
self-signed cert is fine — do not bother provisioning a real one.

## Server: deploy on the LGA VPS

The LGA VPS (Hetzner, Nuremberg) runs the whole stack via Docker Compose in
`/lga/compose.yml`. The netdiag server is added as a **standalone compose
project** under `deploy/` in the netdiag repo — deliberately not merged into
`/lga/compose.yml` — because it is a diagnostic tool, not part of the LGA
service topology, and it needs `network_mode: host` which is awkward to mix in.

### Ports it binds (all on the VPS public IP)

| Proto | Port  | Purpose                        | `NETDIAG_*` env        |
| ----- | ----- | ------------------------------ | ---------------------- |
| TCP   | 443   | test 1 + HTTPS control plane   | `NETDIAG_HTTPS`        |
| TCP   | 8443  | test 2 (TCP ACK exchange)      | `NETDIAG_TCP`          |
| UDP   | 60000 | test 3 (UDP ACK datagrams)     | `NETDIAG_UDP`          |
| UDP   | 51820 | test 4 (WireGuard handshake)   | `NETDIAG_WG_51820`     |
| UDP   | 443   | test 5 (WireGuard on 443)      | `NETDIAG_WG_443`       |

TCP/443 and UDP/443 coexist on the same port — that overlap is exactly what
test 5 probes. **Port 443 must be free** before deploying: nothing in the LGA
stack publishes it today (only `4000` for LiteLLM is public, the rest are
bound to `127.0.0.1`), but verify on the box before you start:

```sh
ss -ltnup | grep -E ':(443|8443|51820|60000)\b'   # expect no listener
```

> **Headline risk: TCP 443.** The LGA VPS does not run a public web server
> today, so 443 should be free — but it is the one port that, if anything else
> later claims it, breaks netdiag's control plane. Keep it out of other
> services. The Windows client hard-codes the five ports, so the server must
> keep its default ports for the client to reach it unchanged.

### Deploy

```sh
# On the VPS
ssh <lga-vps>
git clone git@github.com:rthomazel/netdiag.git ~/netdiag
cd ~/netdiag
git checkout main

docker compose -f deploy/docker-compose.yml up -d --build
```

`network_mode: host` means there is no `ports:` block — the five listeners bind
directly on the VPS's public interface at the `NETDIAG_*` defaults. The build
passes `GOPROXY=https://goproxy.cn,direct` because the VPS network blocks
`proxy.golang.org` (same constraint the LGA Go services work around).

### Smoke test from the VPS

```sh
# Control plane answers and hands out the WG device public keys
curl -sk https://127.0.0.1/wg
# => {"wg51820":"<64-hex>","wg443":"<64-hex>"}

# Any other HTTPS path (incl. the client's /probe) answers with the JSON
# Result carrying the source it observed (here: loopback)
curl -sk https://127.0.0.1/probe
# => {"name":"https443","status":"pass","src":"127.0.0.1:38948"}
```

Then the real run from the Windows client against the VPS public IP. The
server's log is the NAT report — each line is a test name + the source
IP:port it observed:

```sh
docker compose -f deploy/docker-compose.yml logs -f netdiag-server
# netdiag server: https=:443 tcp=:8443 udp=:60000 wg51820=:51820 wg443=:443
# https443 from 203.0.113.7:54780
# tcp8443 from 203.0.113.7:39626
# udp from 203.0.113.7:56769
```

If the client and VPS are on the same Tailscale network you can also point the
client at the VPS's tailscale IP instead of the public one — the server binds
all interfaces. (That changes what you are measuring to the Tailscale path, so
for the actual NAT diagnostic use the public IP.)

### Ops

```sh
docker compose -f deploy/docker-compose.yml logs -f netdiag-server    # live log
docker compose -f deploy/docker-compose.yml restart netdiag-server    # restart
docker compose -f deploy/docker-compose.yml down                      # remove
git -C ~/netdiag pull && docker compose -f deploy/docker-compose.yml up -d --build   # update
```

`restart: always` is set, so the container survives VPS reboots. No state to
back up — the WG keypairs are generated fresh at each start (a client run
re-registers its own key, so a server restart mid-investigation just means
re-running the client).

### Hetzner firewall

Make sure the Hetzner firewall allows inbound TCP 443, TCP 8443, UDP 60000,
and UDP 51820/443 from the client's location (or from anywhere, if you want
to run the diagnostic from multiple networks — that is the point of the tool).
The LGA stack already needs 4000 open for LiteLLM, so a public-inbound rule
exists; add the netdiag ports to it if they are not covered.
