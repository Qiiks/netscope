# Shared scopes

A shared scope lets more than one program manage the same process without
fighting over its cgroup. ExitLink and Dropship are the motivating pair: one
routes the game's traffic, the other filters it, and Linux gives a process
exactly one cgroup. If each tool created its own cgroup, whichever attached
second would silently break the other tool's selector.

## Identity

A scope is shared on a normalized process identity plus the target UID:

| Input | Key |
|---|---|
| `--process Overwatch.exe` | `name:overwatch`, uid |
| `--wine /games/Overwatch/Overwatch.exe` | `name:overwatch`, uid |
| `--exe /usr/bin/game` | `native:dev:ino`, uid |
| `--steam 2357570` | `steam:2357570`, uid |

The last path component is lowercased and a trailing `.exe` is dropped, so
`Overwatch`, `Overwatch.exe`, `overwatch.exe`, and a Wine PE path all land on
one scope. A native target stays exact by device and inode; it never merges
with a name.

Two consumers with the same key share one profile, one cgroup, one mark, and
one nftables table. The first consumer creates it; the last consumer to close
removes it.

## Claims

`open` registers a consumer:

```sh
sudo netscope --uid "$(id -u)" open --consumer exitlink --name overwatch --process Overwatch.exe --route tun0
sudo netscope --uid "$(id -u)" open --consumer dropship --process Overwatch.exe --filter allow \
  --deny-cidr 64.224.26.0/23
```

Both commands return the same profile. An API client that keeps its control
connection open can use a peer hold; the claim is released when that connection
closes, which is the right lifetime for a running app. The CLI itself is
one-shot, so it always uses a persistent hold. A consumer that crashes without
closing a peer claim is cleaned up by the daemon; a persistent claim stays until
`netscope close` or `netscope remove`.

`close` releases one consumer:

```sh
sudo netscope close --consumer dropship overwatch
```

The profile remains while any claim remains. The last `close` removes the
cgroup, nftables table, routing table, and fanotify holds.

`resolve` finds the shared profile from a target or an id:

```sh
sudo netscope --uid "$(id -u)" resolve --process Overwatch.exe
sudo netscope resolve --profile overwatch
```

## Policies

Each consumer owns its own policy. One profile can carry one route policy and
any number of filter policies:

| Consumer | Policy | Effect |
|---|---|---|
| exitlink | route `tun0` | mark packets for the tunnel table |
| dropship | filter allow, deny `64.224.26.0/23` | drop only the listed destinations; everything else falls through |

A second consumer cannot take the route: route ownership is exclusive. Filters
compose before the route mark: a drop from any filter is terminal for that
packet, so a Dropship drop never reaches ExitLink's mark. In a drop filter,
loopback is always accepted; an allow filter can deny it explicitly.
Route policies can also exclude destinations:

```sh
sudo netscope policy overwatch --consumer exitlink --route tun0 \
  --except 203.0.113.0/24
```

An exception gets an `ip rule` to `main` before the profile's mark rule, so the
listed destination stays direct while everything else uses the tunnel.

## Launching and attaching

For a name target, `open` also installs a pre-exec hold on the Wine and Proton
loader binaries it can find. When a loader is about to exec, the daemon checks
whether its launcher ancestry or the loader's own command line names the
scope's target; if it does, the loader is moved into the cgroup before it runs.
The game process inherits that cgroup, so its first socket is already scoped.
The daemon then learns the PE path from the loader's command line and holds the
PE open as well. A Wine target stores the PE path and holds the PE directly.

Already-running processes still attach late on the poll interval, and their
existing sockets are marked with the profile's firewall mark. A name scope is
therefore pre-exec for the next launch and late-with-marking for a process that
was already running.

## Protocol

The daemon's control socket speaks one JSON request per line. A consumer can
use the `netscope` CLI or speak the protocol directly:

```json
{"id":1,"op":"open","consumer":"exitlink","name":"overwatch","target":{"kind":"name","name":"Overwatch.exe"},"target_uid":1000,"hold":"peer"}
{"id":2,"op":"set_policy","profile":"overwatch","consumer":"exitlink","policy":{"kind":"route","interface":"tun0"}}
{"id":3,"op":"close","profile":"overwatch","consumer":"exitlink"}
```

`open` is idempotent for a `(target, target_uid, consumer)` tuple. `set_policy`
replaces that consumer's policy atomically and rolls back on failure. The
daemon serializes every cgroup, nftables, and routing mutation behind one lock,
so two consumers cannot interleave a half-written ruleset.

Full schema, error semantics, every operation, and multi-language client
examples are in [Daemon Protocol & SDK](protocol.md).

## Limits

- A name target attaches every process with that name under the target UID.
  There is no per-install-path identity for an already-running process.
- Do not create two profiles whose targets overlap the same process. A
  process has one cgroup and one firewall mark, so the profiles would fight
  over it. Share one scope instead.
- Only one route policy per shared profile; use separate profiles for two
  different tunnels.
- The loader hold covers Wine/Proton binaries that the daemon can discover and
  whose launcher ancestry or command line names the target. A custom Wine build
  outside the scanned directories, or a launcher whose command line does not
  name the game, falls back to late attach. The PE path is learned only when
  the launcher passes an absolute, `Z:\`, or `C:\` path; a bare basename still
  gets the loader hold but no PE hold.
- `filter` and `route` are the only policy kinds. There is no TCP redirect,
  proxy, or per-destination policy in this layer.
