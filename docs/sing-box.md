# The sing-box core

N2X runs two proxy cores in one process. `core/xray` wraps
[Xray-core](https://github.com/xtls/xray-core) and `core/sing` wraps
[sing-box](https://github.com/SagerNet/sing-box). Each panel node is served by
exactly one of them; `core/selector.go` decides which.

## Which core serves what

| Node type     | xray | sing | Notes |
| ------------- | :--: | :--: | ----- |
| `vless`       |  ✅  |  ✅  | |
| `vmess`       |  ✅  |  ✅  | |
| `trojan`      |  ✅  |  ✅  | |
| `shadowsocks` |  ✅  |  ✅  | |
| `anytls`      |  ✅  |  ✅  | Both implementations are kept on purpose — see below |
| `artx`        |  ✅  |  —   | N2X-specific, xray only |
| `hysteria`    |  —   |  ✅  | Requires the `with_quic` build tag |
| `hysteria2`   |  —   |  ✅  | Requires the `with_quic` build tag |
| `tuic`        |  —   |  ✅  | Requires the `with_quic` build tag |
| `shadowtls`   |  —   |  ✅  | |
| `naive`       |  —   |  ✅  | |

`N2X version` prints the cores actually compiled into a binary.

## Choosing a core

`Options.Core` (a core type) or `Options.CoreName` (a name, for several cores
of the same type) pins a node. When neither is set, the selector walks the
configured cores in the order given by `corePriority` in `core/selector.go` —
currently `xray`, then `sing` — and takes the first that supports the node
type.

That order matters because Go randomises map iteration: without it, an
`anytls` node would land on a different core from one restart to the next.
Defaulting to xray also means an existing deployment keeps the behaviour it
had before the sing core learned the same protocol.

**AnyTLS is served by both cores at once.** They are separate implementations
(xray's native `proxy/anytls` and sing-box's `protocol/anytls`), they can run
side by side on different nodes and ports, and a node picks one with
`"Core": "xray"` or `"Core": "sing"`. An `anytls` node with no `Core` set goes
to xray.

## Node types are not always panel types

`NodeType` in `config.json` is what N2X asks the panel for; it is not always
what the panel serves back.

**Hysteria is one panel type with a version field.** X-Board (and V2board)
model Hysteria and Hysteria2 as a single `hysteria` node type carrying
`"version": 1` or `"version": 2` — the panel UI shows it as a 协议版本
dropdown. `GetNodeInfo` reads that field and rewrites `NodeInfo.Type` to
`hysteria` or `hysteria2` before the core selector sees it, so the right
inbound is built either way:

| `NodeType` in config | panel `version` | inbound built |
| --- | --- | --- |
| `hysteria` | 2 | Hysteria2 |
| `hysteria` | 1 | Hysteria |
| `hysteria2` | 2 | Hysteria2 |
| `hysteria2` | 1 | Hysteria — the panel wins |
| either | absent | falls back to the configured type |

Prefer `"NodeType": "hysteria"`. X-Board aliases `hysteria2` back to
`hysteria`, but stock V2board has no such alias and rejects it.

The two generations also disagree on obfuscation: v1 sends the password in
`obfs`, v2 sends the type in `obfs` and the password in `obfs-password`.
`buildHysteria2Obfs` treats a lone `obfs` as a Salamander password so a panel
that only fills one field still works.

**TUIC is v5 only.** sing-box does not implement v4. A node the panel pinned
to an older generation is rejected at parse time rather than served as v5,
which would fail every client handshake with nothing useful in the log.

**ShadowTLS needs panel support.** It is not in X-Board's `VALID_TYPES`
(`hysteria, vless, trojan, vmess, tuic, shadowsocks, anytls, artx, socks,
naive, http, mieru`), so the panel rejects `node_type=shadowtls` before N2X
sees a response. The core supports it; the panel has to grow the type first.

## ShadowTLS is two inbounds

sing-box's ShadowTLS inbound performs the camouflage handshake against a real
upstream site and then hands the decrypted stream to a *detour* inbound. N2X
builds both:

```
                    :8443                       loopback:<ephemeral>
client ──────▶ <tag> (shadowtls) ──detour──▶ <tag>$detour (shadowsocks)
```

The inner Shadowsocks inbound owns per-user credentials, so a ShadowTLS node
supports live user add/remove like any other protocol. `HookServer.resolveTag`
maps the detour tag back to the node tag so limits and traffic accounting are
attributed to the node rather than the internal inbound.

The detour still binds a socket — sing-box always opens one — so it is pinned
to `127.0.0.1` on an ephemeral port where it is unreachable from off-host.

The ShadowTLS layer itself uses the node-level password from the panel; the
per-user secrets live in the Shadowsocks layer. Set `CertMode: "none"`: a
ShadowTLS node needs no certificate of its own, since it borrows the handshake
target's.

## NaiveProxy rebuilds its listener

This is the one protocol without live user management. sing-box's naive
inbound builds its authenticator once, at construction, from a fixed user
list, and refuses to start with an empty one.

`core/sing/naive.go` therefore keeps the node's user set in memory and
recreates the inbound whenever that set changes. Consequences:

- The node's listener is not opened until its first user arrives.
- Adding or removing a user re-binds the port and drops connections that are
  in flight. It happens only when the panel actually changes this node's
  users, not on every sync.
- The old inbound is removed *before* the replacement is created, because
  sing-box's inbound manager starts a new inbound before closing the one it
  replaces, and creating first would fail to bind a port still in use.

If that trade-off is unacceptable for a deployment, do not use naive nodes.

## Transports the sing core cannot serve

`buildV2RayTransport` in `core/sing/inbound.go` maps a panel's `network` onto a
sing-box V2Ray transport. It knows `tcp` (an empty network means TCP), `ws`,
`grpc` and `httpupgrade`, and it **rejects everything else** — `xhttp`,
`splithttp`, `kcp`, `quic`, `h2`.

That rejection is deliberate. Falling back to plain TCP, which is what this
code used to do, brings the listener up on a transport no client is speaking:
the node looks healthy, every connection fails, and nothing in the log points
at the cause. An xhttp node belongs on the xray core — pin it with
`"Core": "xray"`.

## Hysteria port hopping is a firewall rule

Port hopping is a client-side behaviour: the client keeps moving the
destination port around inside a range so a censor cannot pin the flow to one
UDP port. The server has nothing to negotiate — it only has to answer on every
port in the range.

sing-box has no server-side option for this. `server_ports` and `hop_interval`
exist on the Hysteria **outbound** only (`option/hysteria2.go`), and binding
one listener per port would cost a UDP socket per port. So N2X does what
Hysteria's own documentation does: a nat PREROUTING rule that redirects the
whole range to the port the node listens on.

`common/porthop` owns those rules. Each carries a `N2X:porthop:<tag>` comment.
That comment is what makes removal exact — and it is also the only thing
removal matches on, so a redirect an operator installed by hand carries none of
ours and is never touched. The rules are installed after the inbound is up
(`AddNode`), removed with the node (`DelNode`), and cleared for every node on
shutdown (`Close`).

Before installing, `Apply` reads the chain back (`iptables -t nat -S
PREROUTING`) and deletes every rule carrying this node's comment, not just the
ones this process remembers installing. A node killed with `SIGKILL`, an OOM
kill or a power cut leaves its redirect in the table, and appending a second
copy on the next start would grow the chain by one stale rule per unclean
restart. One case is still left to the operator: a node deleted from the panel
while N2X was down keeps its rule, because nothing asks about that tag again.
Find those with `iptables -t nat -S PREROUTING | grep N2X:porthop`.

The range comes from the panel's `server_ports` on a `hysteria`/`hysteria2`
node — a string, a list, or bare numbers all decode — and falls back to
`SingOptions.HysteriaOptions.PortHopping` for panels that cannot express it:

```json
"HysteriaOptions": {
  "PortHopping": ["20000-30000"]
}
```

Two consequences worth knowing before turning it on:

- **Linux only, and N2X must be able to run `iptables`.** `ip6tables` is used
  too when present; a host without it configures IPv4 only. Anywhere else,
  a node that asks for port hopping fails to start rather than coming up
  quietly without the redirect.
- **A node whose redirect cannot be installed is taken back down.** Serving
  hysteria on one port while clients hop across a range reaches the operator
  as unexplained packet loss, which is worse than a node that says why it
  stopped.

## Multiplex Brutal is a kernel module, not a sing-box feature

`buildMultiplex` in `core/sing/inbound.go` passes `SingOptions.Multiplex.Brutal`
through to sing-box as `option.BrutalOptions`. What that eventually performs is
a pair of `setsockopt` calls on the server side of the multiplex connection:
sing-mux sets `TCP_CONGESTION` to `brutal`, then writes a `TCP_BRUTAL_PARAMS`
struct. Both fail unless the [tcp-brutal](https://github.com/HyNetworks/tcp-brutal)
kernel module is installed on the node. The xray core has no equivalent — there
is no `TCP_BRUTAL` anywhere in it — so this setting means something only on a
`"Core": "sing"` node.

Failure is quiet by design. When the `setsockopt` fails, sing-mux answers the
client's brutal request with `WriteBrutalResponse(conn, 0, false, ...)` and the
session continues as ordinary multiplex without brutal. Nothing surfaces in the
node's log. "Brutal is enabled and changes nothing" is what a missing — or
refusing — module looks like from the outside.

### tcp-brutal v2 on the node

v2 still accepts the 12-byte v1 parameter struct that sing-mux writes, so
upgrading the module on a node changes nothing above. Two of its new behaviours
are worth knowing before an operator reaches for them:

- **Destination rules lock the connection, which switches mux brutal off.**
  `brutalctl add <prefix> <mbps>` installs a route carrying
  `congctl lock brutal`. On a connection covered by it, sing-mux's
  `setsockopt(TCP_CONGESTION, "brutal")` returns `EPERM` — brutal is already
  running, but the socket may no longer say so — and the quiet fallback above
  takes over. The "destination" of a proxy server's traffic is the client's own
  address, so a rule added to speed one client up is exactly the rule that
  disables that client's mux brutal. Use `brutalctl add ... nolock` on nodes
  serving mux brutal clients, or leave those clients unruled.
- **Destination rules do not replace the limiter.** They key on destination
  prefix, i.e. client IP: dynamic, shared by every user behind one NAT, gone
  after a reboot, and needing a root-side `brutalctl` sync on each user change.
  Per-user speed limits stay where they are, in `limiter/limiter.go`.

v2's `group_id` — several connections sharing one rate without multiplexing
being involved at all — is the part that would map onto N2X's per-user model,
but sing-mux's `TCPBrutalParams` carries only `Rate` and `CwndGain`. There is
nothing to do on this side until upstream adds the field.

## Naive nodes also serve plain HTTPS proxy clients

The pinned sing-box fork (`Designdocs/sing-box_mod`, commit a7039e06) makes the
naive inbound answer two kinds of client on one port with one user list:

- A request carrying the naive `Padding` header is a naive client and gets the
  padded tunnel exactly as before, including the silent connection drop on a
  bad request or wrong credentials.
- A request without it is a plain HTTPS proxy client: a browser extension,
  `curl -x https://…`, anything speaking RFC 9110 CONNECT with Basic auth.
  CONNECT tunnels carry no padding frames and absolute-URI requests for
  `http://` origins are forwarded through the router, on HTTP/1.1 and HTTP/2
  alike.
- A plain request with a missing or wrong `Proxy-Authorization` is answered
  `404` with **no challenge**, CONNECT included, so an active prober that holds
  no credentials sees an empty web server and never learns a proxy is there.
  The one exception is the client's own *probe host*: the first 16 hex
  characters of `sha256("<username>:<password>")` followed by `.invalid`. A
  request for it earns the `407 Basic` challenge a browser needs before it
  will send credentials at all; once authenticated it is answered `204` and
  never routed. The browser extension derives the same host, requests it right
  after applying its proxy policy, and from then on the browser sends
  `Proxy-Authorization` pre-emptively on every CONNECT. The derivation is a
  contract pinned by `TestProbeHostDerivationIsPinned` on the fork side.
- An origin-form request (`GET /` addressed to the node host itself) is not a
  proxy request either and is answered `404`: the extension measures latency
  with exactly such a request, and Chromium refuses a `407` that arrives
  outside a proxy exchange (`ERR_UNEXPECTED_PROXY_AUTH`).

Both paths reach the router with the same user attribution, so limits and
traffic accounting do not distinguish them. Nothing in N2X changes: the node's
users, port and certificate are shared, and the probe host index is built from
the same user list the inbound is rebuilt with.

## Protocol parameters: panel first, config second

Several protocol settings have no place in a panel's node payload, or have one
only on some panels. Each of them therefore resolves the same way: **what the
panel sends wins, and the node-local config fills what it left empty.** The
resolvers live next to the inbound they configure (`tuicTimings`,
`hysteriaQUICTuning`, `buildHysteria2Masquerade`, `buildHandshakeForServerName`).

| Setting | Panel field | Local config |
| --- | --- | --- |
| Hysteria port hopping | `server_ports` | `HysteriaOptions.PortHopping` |
| Hysteria2 masquerade | `masquerade` | `HysteriaOptions.Masquerade` |
| Brutal debug logging | — | `HysteriaOptions.BrutalDebug` |
| Hysteria v1 QUIC windows | `recv_window_conn`, `recv_window_client`, `max_conn_client`, `disable_mtu_discovery` | the same names under `HysteriaOptions` |
| TUIC auth timeout / heartbeat | `auth_timeout`, `heartbeat` | `TuicOptions.AuthTimeout`, `TuicOptions.Heartbeat` |
| TUIC congestion control | `congestion_control` | `TuicOptions.CongestionControl` |
| ShadowTLS per-SNI handshake | `handshake_for_server_name` | `ShadowTLSOptions.HandshakeForServerName` |

Panel durations decode from either form — `"10s"` or a bare number of seconds
(`panel.Duration`) — and port ranges from a string, a list, or bare numbers
(`panel.PortRanges`).

```json
"HysteriaOptions": {
  "PortHopping": ["20000-30000"],
  "Masquerade": "https://news.example.com",
  "ReceiveWindowConn": 15728640,
  "MaxConnClient": 1024
},
"TuicOptions": {
  "AuthTimeout": "3s",
  "Heartbeat": "10s",
  "CongestionControl": "bbr"
},
"ShadowTLSOptions": {
  "HandshakeForServerName": {
    "www.apple.com": { "Server": "www.apple.com", "ServerPort": 443 }
  }
}
```

Two details worth knowing:

- **The Hysteria2 masquerade reaches sing-box as written, with one
  exception.** Both forms it accepts work from the panel — a URL string
  (`"https://example.com"` reverse proxies that site, `"file:///var/www"`
  serves a directory) and the object form with `status_code`/`headers`/
  `content`. The local config offers the URL form only, which is what an
  operator writes by hand. An unusable value fails the node rather than
  starting it without camouflage: sing-box accepts `file`, `http` and `https`
  URLs only.

  The exception is `n2x://decoy`, the same selector an xray fallback takes
  (`core/sing/decoy_masquerade.go`). It expands to the origin of the companion
  web service installed on this host — `http://127.0.0.1:60443/` by default,
  or whatever `N2X_ARTX_DECOY_LISTEN` points at — so the masquerade site and
  the fallback site are the same page, configured in one place. Both spellings
  work: the bare string, and the object form with `"url": "n2x://decoy"`.
- **The QUIC window settings are Hysteria v1 only.** Hysteria2 manages its own
  windows; sing-box's Hysteria2 inbound has no equivalent options.

## Why the dependency pins are what they are

`go.mod` pins three sing-box-adjacent modules. They are load-bearing, and
bumping any of them without reading this section will break the build.

```
replace github.com/sagernet/sing-box  => github.com/wyx2685/sing-box_mod v1.13.0-alpha.5.0.20251202212447-8d054dcd8bfe
replace github.com/sagernet/quic-go   => github.com/sagernet/quic-go v0.59.0-sing-box-mod.2
replace github.com/sagernet/sing-quic => github.com/sagernet/sing-quic v0.6.3
```

**Why the fork.** Upstream sing-box has no per-inbound `AddUsers`/`DelUsers`
API — a panel agent needs to add and remove users without restarting a
listener, and upstream only offers `UpdateUsers` on Shadowsocks. The
`wyx2685/sing-box_mod` fork adds `AddUsers`/`DelUsers` to anytls, trojan,
hysteria, hysteria2, vmess, vless, tuic and shadowsocks. Its `dev-next` branch
has not moved since 2025-12-02, so the pin is the fork's tip.

**Why those specific quic pins.** Two constraints collide:

1. Xray-core needs `github.com/apernet/quic-go` (its XHTTP/splithttp and
   hysteria transports), which requires the **qpack v0.6** API —
   `qpack.NewDecoder()` with no arguments.
2. The sing-box fork's default stack (`sing-quic v0.6.0-beta.4` →
   `sagernet/quic-go v0.55`) requires the **qpack v0.5** API —
   `qpack.NewDecoder(func)` plus `DecodeFull`.

Both resolve to the same module path, `github.com/quic-go/qpack`, so only one
version can be selected. Pinning it to v0.5.1 compiles the sing core but
breaks Xray's XHTTP transport.

`sagernet/quic-go v0.59.0-sing-box-mod.2` is the *oldest* sing-box quic-go
that already uses the qpack v0.6 API, and `sing-quic v0.6.3` is the newest
sing-quic that builds against it. That combination lets both cores share
qpack v0.6.

**Why not just move everything forward.** Newer sing-quic (v0.6.4+) needs
`github.com/sagernet/sing` v0.8.5–v0.8.8, where `common/tls.Config` has a
`HandshakeTimeout()` method. That method does not exist in sing v0.8.9, which
is what Xray-core's `common/singbridge` compiles against, and the Dec-2025
sing-box fork does not implement it either. There is no single `sing` version
that satisfies a newer sing-quic *and* Xray-core, so the stack stays here.

**Upgrade checklist.** After changing any of these pins, verify all of:

```bash
GOEXPERIMENT=jsonv2 go build -tags "xray sing with_quic with_grpc with_utls with_acme" .
GOEXPERIMENT=jsonv2 go build github.com/xtls/xray-core/transport/internet/splithttp
GOEXPERIMENT=jsonv2 go test ./core/...
```

The splithttp build is the canary: it is the package that fails first when
qpack is dragged backwards.

## The custom registry

`core/sing/registry.go` replaces sing-box's own `include` package. N2X is a
server-side agent, so it registers only the inbounds it serves plus the
`direct`/`block`/`dns` outbounds and the DNS transports; TUN, redirect/TProxy,
SOCKS, HTTP, mixed, Tor, SSH, WireGuard, Tailscale and the management services
are left out.

That is partly about binary size and partly a hard requirement: `include`
imports `protocol/socks`, `protocol/mixed` and `protocol/tor`, and those three
packages call `socks.HandleConnectionEx` with a signature that no longer
exists in the `sing` version Xray-core pins us to. Not importing them is what
makes the two cores co-installable.

Practical consequence: a custom base config supplied through the sing core's
`OriginalPath` can only use the registered types. Adding one back is a matter
of registering it in `registry.go` — provided it still compiles.

## Build tags

| Tag         | Effect |
| ----------- | ------ |
| `xray`      | Links the xray core (`core/imports/xray.go`) |
| `sing`      | Links the sing core (`core/imports/sing.go`) |
| `with_quic` | Enables Hysteria, Hysteria2 and TUIC in the sing core |

Without `with_quic`, `Sing.Protocols()` omits the QUIC node types, so the
selector will not route a node to a core that cannot listen for it.
