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

### Fixed

- The systemd unit now keeps `ProtectSystem=strict` while allowing the daemon
  to create `/sys/fs/cgroup/netscope` (`CAP_DAC_OVERRIDE` plus the cgroup root
  in `ReadWritePaths`).
- Privileged tests cover filter/route composition, loopback exceptions, mark
  isolation between profiles, and a fake-game allow-then-drop transition.

## 0.2.0

- Name-based process targets (`--process`), late socket marking, and the
  Windows/Wine pre-open path.
