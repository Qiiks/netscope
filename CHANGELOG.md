## Unreleased

### Fixed

- A UDP-only route marks only datagram sockets. `SO_MARK` is protocol-agnostic
  and the fwmark ip rule reads it directly, so a marked TCP socket sent its
  handshake into a route that carries only datagrams. Games lost their auth
  connections while gameplay traffic kept working.
- `open` no longer marks the target's sockets before its policy arrives: the
  scope is created first and the policy is set in a second request, so the
  first attach used to mark every socket with a bare route mark.
- A marking pass that marked nothing stays retryable, so a later policy change
  or a socket created in the same pass is still marked.

### Added

- `--except-sport` pins UDP source ports (route policies carry
  `except_sports`). A socket that already had a flow when the route opened stays
  direct — rerouting a live flow changes its game-visible source and the game
  server drops the session. Pinned sockets are never `SO_MARK`ed, and the nft
  selector accepts them ahead of the mark rule.

# Changelog

## Unreleased

### Added

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

### Fixed

- A UDP-only route no longer marks TCP sockets. `SO_MARK` is protocol-agnostic,
  so a marked stream socket took the fwmark into the UDP-only route and its
  handshake was lost — a game's auth connection dropped while the tunnel was
  up. Datagram sockets are now the only ones marked for `--udp` profiles.
- The daemon's seccomp allow-list now includes `pidfd_getfd`. `clear_mark_all`
  uses it on the first reconcile; the hardened unit previously killed
  `netscoped` with `SIGSYS` before it served a request, leaving ExitLink on its
  sport-rule fallback.
- The systemd unit now keeps `ProtectSystem=strict` while allowing the daemon
  to create `/sys/fs/cgroup/netscope` (`CAP_DAC_OVERRIDE` plus the cgroup root
  in `ReadWritePaths`).
- Privileged tests cover filter/route composition, loopback exceptions, mark
  isolation between profiles, and a fake-game allow-then-drop transition.

## 0.2.0

- Name-based process targets (`--process`), late socket marking, and the
  Windows/Wine pre-open path.
