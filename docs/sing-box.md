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
