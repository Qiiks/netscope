# Troubleshooting

Start with the two commands that answer most questions:

```sh
netscope status
sudo netscope doctor
```

`status` shows whether the daemon is reachable and what each profile currently has attached. `doctor` checks seven things: root, kernel, cgroup v2, tools, daemon, state and config, and profile runtime. Both exit non-zero on failure; see [CLI reference](cli.md#exit-codes). Run `doctor` with `sudo`; without root the `root` check fails and doctor exits `1`.

## Checklist

| Symptom | Check | Likely cause and fix |
|---|---|---|
| `daemon not running` (exit `3`) | `systemctl status netscoped` | Start it: `sudo systemctl start netscoped`. If it exits immediately, read `journalctl -u netscoped -n 50`. |
| `permission denied` (exit `4`) | `id -nG` includes `netscope` | Add the user and log in again: `sudo usermod -aG netscope "$USER"`. A new shell is not enough; the session must be new. |
| `doctor` fails on the kernel | `uname -r` | Kernel older than 5.13 cannot hold an exec. Upgrade the kernel. |
| `doctor` fails on cgroups | `stat -fc %T /sys/fs/cgroup` | Not `cgroup2fs` means a v1 or hybrid hierarchy. Boot with unified cgroup v2. |
| `nft: command not found` | `command -v nft` | Install nftables. |
| `ip: command not found` | `command -v ip` | Install iproute2. |
| `Operation not permitted` from nftables or cgroups | `systemctl cat netscoped` | The daemon is not running as root or lost a required privilege. Run the shipped unit; do not drop capabilities it needs. |
| Config change is ignored | `journalctl -u netscoped -n 50` | The daemon reads the file at startup. Restart it. An unknown key is rejected. |
| `add` says the profile exists | `netscope list` | Names are unique. Remove the old profile or choose another name. |
| `add` fails at the profile limit | `netscope list` | At most 32 profiles. Remove unused ones. |
| App is not scoped | `netscope status`, then `cat /proc/<pid>/cgroup` | The app was already running and attached late, or was never matched. Restart the app from scratch. |
| App is scoped but an old connection still works | `netscope status` shows `late` | Existing sockets keep their original cgroup. Restart the app. |
| Steam game is not scoped | `netscope status` after launching the game | Add the profile before launching, and launch the game through Steam. Restart Steam if it was already running. |
| Wine/Proton game is not scoped | `netscope status` shows `pre-open`, `mixed`, `late`, or `none` | Point `--wine` at the `.exe` the loader actually opens, using an absolute path. Add the profile before launching and restart the game. A `late` attach leaves early sockets unscoped. |
| Process-name target is not scoped | `netscope status` shows `name:<name>`, `cat /proc/<pid>/comm` | The name must match `comm` or an argv basename, case-insensitively. Cross-check the real name with `ps -o comm= -p <pid>`. A `late` attach leaves early sockets unscoped; restart the app after the attach. |
| Route profile has no connectivity | `ip link show <iface>`, `ip route show table <table>` | The interface is down or has no route. The blackhole is doing its job. Bring the tunnel up. |
| Route profile works, then dies when the VPN drops | This is intended | The blackhole rejects traffic while the interface is down. Restore the tunnel or remove the profile. |
| LAN devices unreachable in route mode | Look for `--include-lan` | By default LAN traffic bypasses the tunnel. If the app must reach the LAN through the tunnel, add the flag. Conversely, if you added `--include-lan` and the tunnel does not carry LAN, remove it. |
| IPv6 stops working | `netscope status` | Route mode drops IPv6 unless `--allow-ipv6` is set. Add it only if the tunnel carries IPv6. |
| DNS fails in filter mode | The profile's `--allow-cidr` list | Allow the resolver's address. Loopback resolution through a local stub may still work, but the stub's upstream query is a separate process. |
| DNS fails in route mode | Tunnel DNS configuration | netscope does not configure DNS. Push a resolver through the tunnel or set one manually. |
| Stale tables or rules after a crash | `sudo nft list tables`, `ip rule show` | Stop the daemon, then run `sudo netscope cleanup --all`. See [Cleanup](#cleanup). |
| `cleanup` exits `3` | `systemctl is-active netscoped` | Cleanup refuses to run while the daemon is active. Stop it first. |

## The daemon will not start

```sh
systemctl status netscoped
journalctl -u netscoped -n 100 --no-pager
```

Common causes:

- **Unknown config key.** The config parser rejects unknown fields. Compare `/etc/netscope/config.toml` with [Configuration](configuration.md).
- **cgroup root outside the cgroup2 mount.** `cgroup_root` must be under `/sys/fs/cgroup`.
- **State file unreadable or from a newer version.** Restore a backup or, if you accept losing profile definitions, move the file aside and run `sudo netscope cleanup --all` before starting.
- **Socket path not writable.** `/run/netscope` must exist and be writable by root. The shipped unit creates it.

## The app is not scoped

Check in this order:

1. `netscope list` confirms the profile exists and is enabled.
2. `netscope status` shows a process in `PIDS` while the app runs.
3. `cat /proc/<pid>/cgroup` contains `/netscope/<profile>`.
4. `sudo nft list table inet netscope_filter_<profile>` shows the expected rules.

If `PIDS` is empty, the daemon never matched the process. Typical reasons:

- The executable path resolved differently than you expect. Use `readlink -f /path/to/app` and add that path.
- The app is a script or launcher that execs a different binary. Select the binary that actually opens sockets, or select the launcher if its children stay in the same cgroup.
- The app was already running before the profile existed and the poll fallback did not catch it. Restart it.
- A security policy blocks fanotify. `doctor` reports the attach source; late attachment is reported as `late`.

If `PIDS` is populated but traffic still escapes, the remaining causes are usually existing sockets, DNS handled by another process, or traffic generated by the kernel rather than the app. See [Security](security.md#what-netscope-does-not-protect).

### Wine and Proton

A `--wine` profile attaches when Wine opens the PE, and `status` reports `pre-open`. If the game runs but `PIDS` stays empty:

- `netscope status` should show `wine:/path/to/game.exe`. A file under `steamapps/common/` and its copy under `steamapps/compatdata/<appid>/pfx/drive_c/` are different files. Select the one Wine actually opens, and keep the path absolute.
- The attached process must be a Wine process whose command line names the PE: `wine`, `wine64`, `wine-preloader`, `wine64-preloader`, or a basename containing `wine-preloader`. `wineserver` is never attached; it may open the PE for a loader, but it is shared across Wine applications. A non-Wine process that opens the PE is allowed and left unscoped by design.
- Add the profile before launching the game. If the daemon had to fall back to polling, `status` shows `late` and sockets opened during startup are not covered; restart the game to close the gap.
- Flatpak, Snap, and unusual filesystems are not tested. If the fanotify mark cannot be placed, `status` reports `fanotify unavailable; poll-only`, and the poll fallback attaches late. It also reports `executable missing` when the PE path no longer exists. Restart the app after the profile exists, or report a reproducible case with a support bundle.

## Route mode has no connectivity

```sh
ip link show tun0
ip rule show
ip route show table 20000
nft list table inet netscope_route_<profile>
```

- No `default dev tun0` route means the interface is down or the gateways are wrong. If the tunnel needs a next hop, pass `--gateway` or `--gateway6`.
- The blackhole route at metric 1000 is expected. It is only used when the real route is absent.
- Test from the same terminal and user that launches the app. A different process is not in the profile.
- Confirm the app is attached and that its connections were opened after attachment.

## Cleanup

Use cleanup only when the daemon cannot remove its own state:

```sh
sudo systemctl stop netscoped
sudo netscope cleanup --all
sudo systemctl start netscoped
```

`cleanup --all` removes netscope's nftables tables, policy rules, routes, and cgroups. It refuses to run while the daemon is reachable, because the daemon's health loop would recreate the rules within about ten seconds. `--purge` also removes the persisted profile state and `/etc/netscope/config.toml`; use it only when you intend to start over.

## Before reporting a bug

```sh
sudo netscope doctor --json
sudo netscope support-bundle --include-logs --include-config
```

Review the bundle, then attach it to the issue. Include the exact command, expected behavior, actual behavior, and whether the profile used filter or route mode. See [Support bundle](support-bundle.md).
