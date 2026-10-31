# netscope

Per-app network scoping for Linux. Select an app once. Launch it normally.

> Alpha. Linux only. Kernel 5.13 or newer, cgroup v2, nftables, systemd.

## Why

Most Linux VPN and proxy tools route the whole machine or require a wrapper. netscope gives one application its own cgroup identity and applies a filter or a routing mark to that identity, so the app starts the way you already start it.

## Three pieces

- **Normally launched apps.** `fanotify` catches `exec` and places the process in its profile cgroup before the first socket.
- **Per-app cgroup identity.** nftables matches `socket cgroupv2`, not a process name that can be spoofed.
- **Blackhole fallback while active.** Route profiles use a dedicated table with a blackhole default. If the tunnel interface is down, traffic fails rather than leaking. Daemon death or table removal is fail-open; the docs say so.

## Quick start

```sh
sudo netscope --uid "$(id -u)" add blocked --exe /usr/bin/curl --filter drop
curl --max-time 3 https://example.com
sudo netscope remove blocked
```

Next: [install](install.md), [quickstart](quickstart.md), or [how it works](how-it-works.md).
