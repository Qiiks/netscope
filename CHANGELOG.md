# Changelog

## 0.3.0 — 2026-11-12

### Added

- Ordered route links (`--link iface[@ipv4][#ipv6]`, repeatable) with health
  probes every `probe_interval_ms`. The first healthy link in the list carries
  the profile's default route; three failed probes take a link down, two
  successes bring it back, and a recovered higher-priority link takes over.
  When every link is down the profile blackholes its traffic.
- `status --json` reports a `links` array per profile with `interface`,
  `gateway`, `gateway6`, `phase`, `healthy`, `active`, `rtt_ms`, and
  `last_ok_unix`. The wire `api_version` is unchanged; the field defaults to
  empty for older daemons.
- `--link` is available on `add`, `open`, and `policy`, and conflicts with
  `--route`, `--gateway`, and `--gateway6`.
- `doctor` checks that the control socket is group `netscope`, mode `0660`,
  and connectable, and that each route profile keeps its rules and blackhole
  while a failover default is legitimately absent.
- `probe_interval_ms`, `probe_target`, and `probe_target6` daemon config keys.

### Fixed

- `netscoped.service` keeps `CAP_CHOWN` so the control socket is handed to
  group `netscope`; without it every unprivileged client was denied.
- The health reconciler follows the link monitor's current winner instead of
  resetting a switched default back to the first configured link.
- Link probes bind to the probed interface, clear any inherited mark, and use
  TCP with a one-second timeout, falling back to ICMP when the interface has
  no global source address.

## 0.2.1 — 2026-11-04

### Fixed

- A UDP-only route marks only datagram sockets. `SO_MARK` is protocol-agnostic
  and the fwmark `ip rule` reads it directly, so a marked TCP socket sent its
  handshake into a route that carries only datagrams — a game's auth connection
  dropped while the tunnel stayed up.
- `open` no longer marks the target's sockets before its policy arrives. The
  scope is created first and the policy set in a second request, so the first
  attach used to mark every socket with a bare route mark.
- A marking pass that marked nothing stays retryable, so a later policy change
  or a socket created in the same pass is still marked.
- The daemon's seccomp allow-list now includes `pidfd_getfd`. `clear_mark_all`
  uses it on the first reconcile; the hardened unit previously killed
  `netscoped` with `SIGSYS` before it served a request, leaving ExitLink on its
  sport-rule fallback.
- The systemd unit now keeps `ProtectSystem=strict` while allowing the daemon
  to create `/sys/fs/cgroup/netscope` (`CAP_DAC_OVERRIDE` plus the cgroup root
  in `ReadWritePaths`).

### Added

- `--except-sport` pins UDP source ports (route policies carry `except_sports`).
  A socket that already had a flow when the route opened stays direct:
  rerouting a live flow changes its game-visible source and the peer drops the
  session. Pinned sockets are never `SO_MARK`ed, and the nft selector accepts
  them ahead of the mark rule.
- Shared scopes: one profile per normalized process identity, multiple
  consumers (`open`/`close`), and per-consumer filter or route policies.
- Filter-before-route composition in one nftables table per profile, including
  a loopback exception on routed profiles.
- `resolve` and `policy` commands, plus `open --consumer` on the CLI.
- Loader pre-exec holds for name and Wine targets, so the next launch inherits
  the scope before its first socket; a running process still attaches late.
- Late attach marks existing sockets with the profile firewall mark, so a game
  does not need a restart after the profile is created.
- Route policies accept `--udp` and `--except-port`: only IPv4 UDP is marked,
  so a TCP proxy can own the same process. Port exceptions return before the
  mark.

### Tests

- Privileged tests cover filter/route composition, loopback exceptions, mark
  isolation between profiles, a fake-game allow-then-drop transition, and the
  UDP-only mark scope (datagram only; a pinned source port stays unmarked).

## 0.2.0

- Name-based process targets (`--process`), late socket marking, and the
  Windows/Wine pre-open path.
