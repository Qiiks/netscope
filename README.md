# netscope

Per-application network scoping for Linux: select an app once, launch it normally, and only that app's traffic is filtered or routed.

> Alpha. Linux only. Kernel 5.13 or newer with cgroup v2 and nftables.

## Install

Arch Linux / CachyOS (after the AUR package is published):

```sh
yay -S netscope-bin
sudo systemctl enable --now netscoped
sudo usermod -aG netscope "$USER"
```

Tarball and `cargo install --git` channels are documented in [docs/install.md](docs/install.md). Cargo installs binaries only; the systemd unit, sysusers file, and config come from the tarball or AUR.

## Use

```sh
sudo netscope --uid "$(id -u)" add blocked --exe /usr/bin/curl --filter drop
curl --max-time 3 https://example.com   # fails
sudo netscope remove blocked
```

Route a selected app through a tunnel interface:

```sh
sudo netscope --uid "$(id -u)" add routed --exe /usr/bin/curl --route tun0
```

`netscope status`, `netscope list`, `netscope doctor`, and `netscope support-bundle` cover inspection and troubleshooting. No wrapper is required for native ELF apps; Steam apps are matched by app id.

## How it works

1. `fanotify` holds an `exec` of a selected inode until the daemon has moved the process into `/sys/fs/cgroup/netscope/<profile>`.
2. nftables matches `socket cgroupv2` for that profile and applies a filter or a routing mark.
3. Route profiles set a dedicated routing table with a blackhole fallback. If the configured interface is down, traffic is dropped rather than leaking through the main table.

A polling fallback attaches already-running processes and Steam children when fanotify is unavailable. Existing sockets keep their old cgroup; restart the app for full coverage.

## Security

`netscoped` runs as root and accepts control messages only over a root-owned Unix socket in the `netscope` group. It loads no kernel module and opens no network listener. See [SECURITY.md](SECURITY.md) and [docs/security.md](docs/security.md).

## Support

```sh
sudo netscope support-bundle
```

The bundle is written to `/tmp`, is root-only, and includes a review-before-upload warning. Attach it to a bug report after checking it.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
