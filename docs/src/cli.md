# CLI reference

`netscope` is the unprivileged command-line client. It talks to `netscoped` over a Unix socket and never manipulates nftables or routing itself, except for the explicit `cleanup` recovery command.

```text
netscope [GLOBAL OPTIONS] <COMMAND>
```

## Global options

| Option | Meaning |
|---|---|
| `--socket <path>` | Hidden. Override the control socket. For tests and non-default daemon paths. |
| `--uid <n>` | Hidden, root-only. Target user ID for `add`. When omitted by root, `SUDO_UID` is used. |
| `-h, --help` | Print help. |
| `-V, --version` | Print the client version. |

A regular user in the `netscope` group does not pass `--uid`; their profile belongs to the connecting UID. Root passes `--uid` (or relies on `SUDO_UID`) to create a profile for another user; root `add` with neither fails with exit `2`. A non-root user cannot use `--uid`.

## Exit codes

| Code | Meaning | Typical message |
|---|---|---|
| `0` | Success. | — |
| `1` | Runtime or daemon error, including invalid daemon JSON, API version mismatch, nftables/routing/cgroup failure, an unknown profile, a duplicate profile, the profile limit, a daemon policy rejection that is not a permission error, or a failed `doctor` check. | `netscope: <error>` |
| `2` | Usage or validation error caught by the client: bad flag combination, invalid profile ID, invalid CIDR, invalid gateway, unresolvable `--exe` or `--wine`, invalid Steam app ID, `--no-redact` without `--acknowledge`, or a non-root `--uid`. | `netscope: <error>` |
| `3` | Daemon unavailable, or `cleanup` attempted while the daemon is still running. | `netscope: daemon not running; start with: sudo systemctl start netscoped` |
| `4` | Permission denied, a profile owned by another user, a `target_uid` that does not match the caller, or `support-bundle` invoked without root. | `netscope: permission denied; add your user to the netscope group: sudo usermod -aG netscope $USER` |

`support-bundle` without root exits `4` with `netscope: support-bundle requires root: sudo netscope support-bundle`, unless `--no-redact` is given without `--acknowledge`, which exits `2` first. A non-root `doctor` fails its `root` check and exits `1`, not `4`.

Scripts should branch on `0` versus non-zero, and use `3` to distinguish "daemon down" from a rejected request.

## `status`

```text
netscope status [--json]
```

Prints the daemon version, pid, kernel, cgroup root, and one row per profile. The text form has a daemon header and the same columns as `list`:

```text
DAEMON  netscoped 0.1.0  pid 1234  kernel 6.11.0-arch1-1
CGROUP  /sys/fs/cgroup/netscope
NAME     MODE    ENABLED  TARGET                      ATTACHED  PIDS
blocked  filter  yes      /usr/bin/curl               pre-exec  4242
game     route   yes      wine:/games/Game/Game.exe   pre-open  5150
routed   route   yes      /usr/bin/firefox            late      5150,5151
```

The state path and config path are available in `--json` output.

`ATTACHED` is `pre-exec` when only the native exec hook placed processes, `pre-open` when only the Wine open hook did, and `late` when only the poll fallback did. It is `mixed` when a pre-attach source (`pre-exec` or `pre-open`) and the poll fallback are both present, and `none` when no process is attached. A Wine profile shows its target as `wine:<path>`. `PIDS` is a comma-separated list.

`status` exits `3` when the daemon is not reachable.

## `list`

```text
netscope list [--json]
```

Prints the profile table without the daemon header. Disabled profiles are included. `list` also exits `3` when the daemon is unavailable.

## `add`

```text
netscope add <name> --exe <path> (--filter <drop|allow> [CIDR OPTIONS] | --route <iface> [ROUTE OPTIONS])
netscope add <name> --wine <path> (--filter <drop|allow> [CIDR OPTIONS] | --route <iface> [ROUTE OPTIONS])
netscope add <name> --steam <appid> (--filter <drop|allow> [CIDR OPTIONS] | --route <iface> [ROUTE OPTIONS])
```

Creates a profile. Exactly one of `--exe`, `--wine`, and `--steam` is required, and exactly one of `--filter` and `--route` is required.

| Option | Applies to | Meaning |
|---|---|---|
| `--exe <path>` | Native apps | Executable to select. Resolved against the CLI's current directory, then canonicalized. |
| `--wine <path>` | Wine/Proton apps | Windows PE to select. Must be an absolute path. The daemon canonicalizes it and requires an `MZ` header. |
| `--steam <appid>` | Steam apps | Numeric Steam app ID. Matches the app and its children. |
| `--filter <drop\|allow>` | Filter profiles | Default action. |
| `--allow-cidr <cidr>` | `--filter drop` | Destination to keep reachable. Repeatable. |
| `--deny-cidr <cidr>` | `--filter allow` | Destination to drop. Repeatable; at least one is required. |
| `--route <iface>` | Route profiles | Tunnel interface. |
| `--gateway <ipv4>` | `--route` | IPv4 next hop. |
| `--gateway6 <ipv6>` | `--route --allow-ipv6` | IPv6 next hop. |
| `--include-lan` | `--route` | Route LAN destinations instead of bypassing them. |
| `--allow-ipv6` | `--route` | Carry IPv6; without it, IPv6 is dropped. |

Rules enforced before the daemon is asked:

- Name: `^[a-z0-9][a-z0-9-]{0,31}$`.
- Exactly one target: `--exe`, `--wine`, or `--steam`. Combining them is a usage error.
- `--wine` takes an absolute path to a regular file that starts with `MZ`. The daemon canonicalizes the path and stores its device and inode.
- `--allow-cidr` is rejected with `--filter allow`.
- `--deny-cidr` is rejected with `--filter drop`, and `--filter allow` needs at least one.
- `--gateway` is rejected outside `--route`.
- `--gateway6` is rejected without `--allow-ipv6`.
- `--include-lan` and `--allow-ipv6` are rejected outside `--route`.

On success the daemon creates the cgroup, the nftables table, and, for route profiles, the policy rule and routes. If the app was already running and got attached late, the CLI prints:

```text
existing connections unaffected; restart the app for full coverage
```

```sh
sudo netscope --uid "$(id -u)" add blocked --exe /usr/bin/curl --filter drop
sudo netscope --uid "$(id -u)" add routed --exe /usr/bin/game --route tun0 --include-lan
sudo netscope --uid "$(id -u)" add game --wine /games/Game/Game.exe --filter drop
sudo netscope --uid "$(id -u)" add game-route --wine /games/Game/Game.exe --route tun0
sudo netscope add steam-game --steam 730 --filter drop --allow-cidr 203.0.113.0/24
```

The last example assumes the user is in the `netscope` group and has re-logged in. On success, `add` prints `added <name>`; with a late attach it prints the restart warning on the next line.

For a Wine target the profile attaches when a Wine process opens the PE, which is before the game runs. Launch the game the same way you would without netscope — there is no wrapper. See [Wine and Proton targets](how-it-works.md#wine-and-proton-targets).

## `remove`

```text
netscope remove <name>
```

Deletes the profile's nftables table, policy rule, routes, and cgroup, then prints `removed <name>`. Removing a profile that does not exist is a daemon error (`1`). Removing another user's profile as a non-root user is `4`.

## `enable` and `disable`

```text
netscope enable <name>
netscope disable <name>
```

`disable` stops enforcement for the profile while keeping its definition and cgroup; `enable` restores it. Disabling a route profile removes its mark rules, so its traffic returns to the main table. Both print `enabled <name>` or `disabled <name>` and validate ownership like `remove`.

## `refresh`

```text
netscope refresh
```

Forces an immediate target re-stat and attach pass instead of waiting for `refresh_interval_secs`. It re-resolves each `--exe` or `--wine` target's device and inode and attaches already-running matching processes, then prints `refreshed`. For a Wine target whose file changed, it moves the fanotify mark to the new inode. It does not repair a deleted nftables table; the daemon's health loop does that.

## `doctor`

```text
netscope doctor [--json]
```

Runs seven checks: `root`, `kernel`, `cgroup v2`, `tools` (nftables and iproute2), `daemon` (connectivity and API version), `state + config`, and `profiles` (per-profile runtime). It exits `0` only when no check fails; warnings do not change the exit code.

A non-root run **fails the `root` check and exits `1`**. Other privileged probes that need root report `SKIP`. Run it with `sudo netscope doctor` for the complete report.

`--json` prints a machine-readable report. It is suitable for a bug report and is also included in the support bundle.

## `support-bundle`

```text
netscope support-bundle [--output <path>] [--include-logs] [--include-config]
netscope support-bundle --no-redact --acknowledge
```

Collects diagnostics into a compressed archive. It is root-only; a non-root run exits `4`, except `--no-redact` without `--acknowledge`, which exits `2` before the root check. Without `--output`, it writes `/tmp/netscope-support-<UTC>.tar.zst`.

`logs.txt` and `config.toml` are excluded unless you pass `--include-logs` and `--include-config`. Redaction is on by default; `--no-redact` is refused unless `--acknowledge` is also given, and is intended only for a private reproduction.

On success it prints:

```text
support bundle: <path>
review before uploading
```

The bundle is mode `0600` and chowned back to `SUDO_UID:SUDO_GID` under sudo; review it before uploading. See [Support bundle](support-bundle.md).

## `logs`

```text
netscope logs [-n <lines>]
```

Prints the most recent daemon log lines from the journal. The default is 50; `-n` changes the count. It does not follow, and it does not clear the journal.

## `cleanup`

```text
netscope cleanup --all [--purge]
```

Recovery command for host state left behind by a daemon that could not clean up. It is root-only, requires `--all`, and bypasses the daemon. If the daemon is reachable, it refuses and exits `3`:

```text
cleanup requires the daemon stopped: sudo systemctl stop netscoped
```

`--purge` additionally deletes the configured state file (`/var/lib/netscope/state.json` by default) and `/etc/netscope/config.toml`. Without it, only runtime state is cleaned: every `netscope_*` nftables table, every policy rule and flushed route table in the `20000`–`20031` range, and every profile cgroup under the configured cgroup root. The profile definitions therefore survive and are re-applied when the daemon starts. Cleanup never deletes the control socket, so a stopped daemon cannot be contacted through it.

On success it prints `cleanup complete`. A failed cleanup step prints the step and exits `1`.

```sh
sudo systemctl stop netscoped
sudo netscope cleanup --all
sudo systemctl start netscoped
```

## `--json` output

`status`, `list`, and `doctor` accept `--json`. The client prints the response's `data` field only, pretty-printed, with no success envelope and no error field. Errors are still printed to standard error with the exit code above.

## Examples by outcome

| Command | Exit | Why |
|---|---|---|
| `netscope status` | `0` | Daemon reachable. |
| `netscope status` with the service stopped | `3` | No socket. |
| `netscope add bad_name --exe /bin/true --filter drop` | `2` | Uppercase and underscore are invalid in a profile ID. |
| `netscope add x --exe /bin/true --filter allow` | `2` | `allow` needs at least one `--deny-cidr`. |
| `netscope add x --exe /nope --filter drop` | `2` | Path cannot be resolved. |
| `netscope add x --exe /bin/true --route tun9` | `1` | The daemon cannot install a route through a missing interface. |
| `netscope add x --exe /bin/true --filter drop` as a non-group user | `4` | Socket permission denied. |
| `sudo netscope cleanup --all` while `netscoped` runs | `3` | Cleanup requires the daemon stopped. |
