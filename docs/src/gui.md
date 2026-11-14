# netscope-gui

`netscope-gui` is the desktop inspector for `netscoped`. It shows the links netscoped is using,
the live rates it carries, and the scopes it holds, and it can add, enable, disable, and remove
scopes without a terminal.

```sh
netscope-gui
```

The window connects to the daemon's control socket. If the daemon is not running, the window says
so, keeps retrying every two seconds, and links to **Doctor** for the check and the exact
`systemctl start netscoped` command. If the caller is not in the `netscope` group, the window
shows the `usermod -aG netscope` hint instead of pretending the daemon is absent.

## What the window shows

- **Overview** — the total send and receive rates, a short rate history, one card per link with
  RTT and last-ok age, recent activity, and anything that needs attention.
- **Scopes** — one profile at a time: mode, target, cgroup, mark, policy claims, peer hold, and
  the actions the current permission level allows.
- **Add scope** — a running process or an executable, a filter or ordered-route policy, and a
  peer or persistent hold.
- **Doctor** — the same checks as `netscope doctor`, each with its fix command ready to copy.

## Pause

**Pause updates** freezes the numbers only. netscoped keeps enforcing and carrying traffic; the
paused tooltip says so. Resume with the rail button or the tray menu.

## Tray

The tray icon is `dev.qiiks.netscope` and offers **Show netscope**, **Pause updates**, and
**Quit**. Its tooltip carries the current total throughput. Linux shows the icon where a tray
host runs (KDE, waybar, most bars; GNOME needs an extension).

## Demo mode and screenshots

`--demo` opens the window with a fixed demonstration snapshot. Normal launches never read it.
`--snap` renders a headless PNG and also uses the demonstration snapshot:

```sh
netscope-gui --snap /tmp/overview.png --scene overview --theme dark --size 1100x720
netscope-gui --snap /tmp/narrow.png --scene narrow --size 900x600
```

Scenes: `overview`, `scopes`, `add`, `doctor`, `empty`, `down`, `denied`, `narrow`.

## Scope claims

The window opens peer holds by default: the daemon releases them when this window's control
connection closes, including when the window is closed. A persistent hold survives the window
and a daemon restart and can be released from **Scopes**.
