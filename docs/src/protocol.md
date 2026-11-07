# Daemon Protocol & SDK

`netscoped` exposes its control interface on a Unix domain socket. The socket
speaks newline-delimited JSON (NDJSON): one UTF-8 JSON object per line, one
response per request. This is the same transport the `netscope` CLI uses, so
anything the CLI can do is available to your own program.

The default socket is `/run/netscope/control.sock`. It is created with mode
`0660`, owned by `root:netscope`; a client must be root or a member of the
`netscope` group. The path can be changed with `[daemon] socket_path` in
`/etc/netscope/config.toml`. The protocol version is reported as
`api_version` by `status`; this document describes version `2`.

Two ways to use it:

- **Rust:** the `netscope-client` crate wraps the protocol with typed methods
  and connection lifetime management.
- **Any language:** connect to the socket and exchange NDJSON. Complete Python,
  Go, C, and shell clients are at the end of this page.

## Transport

| Property | Value |
|---|---|
| Socket type | `AF_UNIX`, `SOCK_STREAM` |
| Default path | `/run/netscope/control.sock` |
| Framing | One JSON object per line, terminated by `\n` |
| Encoding | UTF-8 |
| Max request | 256 KiB (`MAX_REQUEST_BYTES`) |
| Max response | 256 KiB (`MAX_RESPONSE_BYTES`) |
| Request timeout | 10 seconds |
| Peer identity | Kernel `SO_PEERCRED` UID of the connecting process |

The daemon reads one line, handles it, writes one line, and repeats. Requests
on one connection are processed in order; a client may send several requests
over the same connection, waiting for each response before sending the next.
A trailing `\r` before the newline is tolerated.

A frame that is invalid ends the conversation: after replying with an error,
the daemon closes the connection. Reconnect for the next request. Anything over
256 KiB, or a line that is not valid JSON, is rejected with request id `0`.
A successful payload that would exceed 256 KiB is replaced by an error response
for the same request id (`response too large`).

## Wire format

### Request envelope

```json
{"id": 1, "op": "status"}
```

| Field | Type | Meaning |
|---|---|---|
| `id` | `u64` | Client-chosen request id, echoed in the response. Use a new value per request. |
| `op` | string | Operation name in `snake_case`. |
| *(args)* | — | Operation-specific fields, flattened at the top level beside `id` and `op`. |

The operation tag is flattened into the envelope, so arguments sit beside
`op`, not inside a nested object.

### Response envelope

```json
{"id": 1, "ok": true, "data": {"api_version": 2}, "error": null}
```

| Field | Type | Meaning |
|---|---|---|
| `id` | `u64` | The request id being answered, or `0` for a framing error. |
| `ok` | bool | `true` for success, `false` for an error. |
| `data` | any | Operation result on success; `null` on error. |
| `error` | string | Human-readable message on failure; `null` on success. |

Both `data` and `error` are always present in the serialized response and are
`null` when not applicable.

### Errors

```json
{"id": 3, "ok": false, "data": null, "error": "profile overwatch not found"}
```

Example error messages:

| Error | Cause |
|---|---|
| `invalid json: ...` | The line was not valid JSON. Answered with id `0`. |
| `invalid request: ...` | Valid JSON, but not a valid request envelope or arguments. Echoes the parsed id when available. |
| `request too large` | The line exceeded 256 KiB. Answered with id `0`. |
| `request timeout` | No complete line arrived within 10 seconds. Answered with id `0`. |
| `permission denied: target_uid must match your uid` | A non-root caller named another user's UID. |
| `permission denied: profile owned by uid N` | The caller is neither root nor the profile owner. |
| `profile <id> not found` | Unknown profile id. |
| `consumer <id> does not hold profile <id>` | Policy or close requested before the consumer called `open`. |
| `route policy already owned by <consumer>` | A second consumer asked for the route on a shared profile. |
| `profile limit reached (N)` | All profile slots are in use; `N` is `max_profiles` (32 by default). |

Scripts should treat any non-zero `ok` as a rejected request and keep the
connection policy simple: reconnect after an error response.

### Versioning

`status` returns `api_version`. A client should read it once per connection
and refuse to continue if it is not the version it was written for. Version 2
covers the shared-scope operations described here.

## Holds and claim lifetime

`open` registers a claim. `hold` chooses how that claim is owned:

| `hold` | Owner | Released when |
|---|---|---|
| `"peer"` | The client socket connection | The client exits, crashes, or closes the connection. The kernel closes the socket; the daemon sees end-of-file and frees the claim and, if it was the last claim, the cgroup, nftables table, and routes. |
| `"persistent"` | The daemon's state file | An explicit `close` or `remove`. It survives a client restart and a daemon restart. |

Use `peer` for a running application or a long-lived helper that can keep one
connection open. The SDK's `Client` owns that connection: keep the `Client`
alive for as long as the scope should exist. Use `persistent` for one-shot
tools, scripts, and the `netscope` CLI itself. The CLI always uses a persistent
claim because it exits after every command.

A consumer that already holds a persistent claim keeps it if it later opens
again with `hold: "peer"`; a peer claim can be upgraded to persistent, never
downgraded.

If a client sends `close` for a profile with other remaining consumers, the
profile survives with those claims. The last `close` removes the profile
(`removed: true`). A peer connection that disappears is released the same way,
consumer by consumer.

## Data types

### TargetSpec

The target is a process identity, not a command line. Its normalized form is
shared across consumers: a Wine PE and a bare process name unify on the
basename (`Overwatch.exe`, `overwatch.exe`, and a Wine path all become
`overwatch`), a native executable stays exact by device and inode, and Steam
targets match by app id.

```json
{"kind": "native", "path": "/usr/bin/curl"}
{"kind": "wine", "path": "/games/Game/Game.exe"}
{"kind": "name", "name": "Overwatch.exe"}
{"kind": "steam", "app_id": 2357570}
```

| `kind` | Fields | Rules |
|---|---|---|
| `native` | `path` | Absolute path to an ELF executable. Canonicalized by the daemon. |
| `wine` | `path` | Absolute path to a Windows PE that starts with an `MZ` header. |
| `name` | `name` | Process `comm` or argv basename. No path separators; at most 64 printable characters. Matched case-insensitively with a trailing `.exe` optionally stripped. |
| `steam` | `app_id` | Non-zero numeric Steam app id. |

### PolicySpec

A policy is either a filter or a route. A shared profile may carry any number
of filter policies, but only one route policy.

**Filter**

```json
{"kind": "filter", "default": "drop", "allow_cidrs": ["203.0.113.0/24"]}
{"kind": "filter", "default": "allow", "deny_cidrs": ["64.224.26.0/23"]}
```

| Field | Type | Meaning |
|---|---|---|
| `default` | `"drop"` or `"allow"` | Action for destinations not listed. |
| `allow_cidrs` | array of strings | Kept reachable with `default: "drop"`. |
| `deny_cidrs` | array of strings | Dropped with `default: "allow"`. |

`default: "drop"` accepts `allow_cidrs` and rejects `deny_cidrs`;
`default: "allow"` is the reverse and requires at least one `deny_cidrs`
entry. A drop filter always accepts loopback unless an allow filter
explicitly denies it. Filters run before the route mark, so a drop from any
consumer is terminal for that packet.

**Route**

```json
{
  "kind": "route",
  "interface": "tun0",
  "gateway": null,
  "gateway6": null,
  "include_lan": false,
  "allow_ipv6": false,
  "udp_only": false,
  "except_ports": [],
  "except_sports": [],
  "except": []
}
```

| Field | Type | Meaning |
|---|---|---|
| `interface` | string | Tunnel interface to route through. |
| `gateway` | string or null | Optional IPv4 next hop. |
| `gateway6` | string or null | Optional IPv6 next hop; requires `allow_ipv6`. |
| `include_lan` | bool | Route LAN destinations instead of bypassing them. Defaults to `false`. |
| `allow_ipv6` | bool | Carry IPv6; without it, IPv6 is dropped. Defaults to `false`. |
| `udp_only` | bool | Mark only IPv4 UDP; TCP keeps the host's normal path. Defaults to `false`. |
| `except_ports` | array of u16 | UDP destination ports that stay direct; requires `udp_only`. Up to 32. |
| `except_sports` | array of u16 | UDP source ports that stay direct, pinning sockets that already existed when the route opened; requires `udp_only`. Up to 64. |
| `except` | array of strings | Destination CIDRs that stay direct, installed as `ip rule`s ahead of the profile's mark. Up to 30. |

Omitted optional fields default to their zero values. `gateway` and
`gateway6` may be omitted or sent as `null`.

### Hold

`"peer"` or `"persistent"`. See [Holds and claim lifetime](#holds-and-claim-lifetime).

## Operations

Every example below is a complete line for the socket. Responses are shown
pretty-printed for readability; on the wire they are one line.

### `status`

Daemon identity and the full profile list.

```json
{"id": 1, "op": "status"}
```

```json
{
  "id": 1,
  "ok": true,
  "data": {
    "api_version": 2,
    "daemon_version": "0.2.1",
    "pid": 1234,
    "kernel": "6.11.0-arch1-1",
    "cgroup_root": "/sys/fs/cgroup/netscope",
    "state_path": "/var/lib/netscope/state.json",
    "config_path": "/etc/netscope/config.toml",
    "profiles": [
      {
        "id": "overwatch",
        "mode": "route",
        "enabled": true,
        "target": "name:Overwatch.exe",
        "cgroup": "/sys/fs/cgroup/netscope/overwatch",
        "cgroup_level": 4,
        "pids": [6120],
        "nft_table": "inet netscope_overwatch",
        "mark": "0x4e53",
        "table": 20000,
        "rule_priority": 1000,
        "attached": "late",
        "healthy": true,
        "warnings": ["name target attaches late; existing sockets are marked"],
        "consumers": ["exitlink"],
        "policies": ["exitlink:route"],
        "generation": 3
      }
    ]
  },
  "error": null
}
```

`ProfileStatus` fields:

| Field | Meaning |
|---|---|
| `id` | Profile id. |
| `mode` | `"route"` when a consumer owns the route, `"filter"` when only filters exist, `"shared"` when no policy is attached. |
| `enabled` | Whether enforcement is active. |
| `target` | Rendered target: `name:<name>`, `wine:<path>`, a native path, or `steam:<app_id>`. |
| `cgroup` | Absolute cgroup path for the profile. |
| `cgroup_level` | cgroup v2 depth used by the nftables `socket cgroupv2` selector. |
| `pids` | Attached process ids, sorted and deduplicated. |
| `nft_table` | `inet <table>` when the profile has policies; empty string otherwise. |
| `mark` | Firewall mark as a hexadecimal string, for example `0x4e53`. |
| `table` | Routing table id. |
| `rule_priority` | `ip rule` priority for the profile's mark. |
| `attached` | `pre-exec`, `pre-open`, `late`, `mixed`, or `none`. |
| `healthy` | Daemon health check result for the profile. |
| `warnings` | Human-readable advisories, possibly empty. |
| `consumers` | Consumer ids holding a claim. |
| `policies` | Policy summaries, one per consumer: `<consumer>:filter` or `<consumer>:route`. |
| `generation` | Incremented when a claim or policy changes; useful for change detection. |

### `open`

Create a shared scope or join an existing one. Idempotent per
`(target, target_uid, consumer)`: an existing consumer gets the same profile
back with a bumped generation.

```json
{"id": 2, "op": "open", "consumer": "exitlink", "target": {"kind": "name", "name": "Overwatch.exe"}, "target_uid": 1000, "name": "overwatch", "hold": "peer"}
```

| Field | Type | Meaning |
|---|---|---|
| `consumer` | string | Lowercase id (`^[a-z][a-z0-9-]{0,31}$`). |
| `target` | TargetSpec | Process identity to scope. |
| `target_uid` | u32 | Owner of the target process. A non-root caller must pass its own UID. |
| `name` | string or omitted | Profile id to use when creating a new scope. Ignored when joining. |
| `hold` | Hold | `"peer"` or `"persistent"`. Required. |

Profile ids match `^[a-z0-9][a-z0-9-]{0,31}$`. Without `name`, the daemon
derives one from the target and UID, for example `overwatch-u1000`.

```json
{
  "id": 2,
  "ok": true,
  "data": {
    "profile": "overwatch",
    "generation": 0,
    "target": "name:Overwatch.exe",
    "target_uid": 1000,
    "state": "active",
    "attached": "late",
    "pids": [6120],
    "consumers": ["exitlink"]
  },
  "error": null
}
```

`ScopeHandle` fields: `profile`, `generation`, `target`, `target_uid`,
`state` (`active` or `disabled`), `attached`, `pids`, `consumers`.

Opening a name target also installs the Wine/Proton loader holds, so the next
launch is moved into the cgroup before its first socket. A running process is
attached on the poll and its existing sockets are marked.

### `set_policy`

Replace one consumer's policy atomically. The consumer must already hold a
claim on the profile. On failure the previous policy is restored.

```json
{"id": 3, "op": "set_policy", "profile": "overwatch", "consumer": "exitlink", "policy": {"kind": "route", "interface": "tun0", "udp_only": true, "except_ports": [53]}}
```

```json
{
  "id": 3,
  "ok": true,
  "data": {
    "id": "overwatch",
    "mode": "route",
    "enabled": true,
    "target": "name:Overwatch.exe",
    "cgroup": "/sys/fs/cgroup/netscope/overwatch",
    "cgroup_level": 4,
    "pids": [6120],
    "nft_table": "inet netscope_overwatch",
    "mark": "0x4e53",
    "table": 20000,
    "rule_priority": 1000,
    "attached": "late",
    "healthy": true,
    "warnings": ["name target attaches late; existing sockets are marked"],
    "consumers": ["exitlink"],
    "policies": ["exitlink:route"],
    "generation": 1
  },
  "error": null
}
```

`data` is a `ProfileStatus`, the same object used in `status` and `list`.
Only one consumer can own the route; a second route request fails with
`route policy already owned by <consumer>`.

### `clear_policy`

Remove one consumer's policy without releasing its claim. The consumer keeps
the scope open and can attach a different policy later.

```json
{"id": 4, "op": "clear_policy", "profile": "overwatch", "consumer": "dropship"}
```

```json
{
  "id": 4,
  "ok": true,
  "data": {
    "id": "overwatch",
    "mode": "route",
    "enabled": true,
    "target": "name:Overwatch.exe",
    "cgroup": "/sys/fs/cgroup/netscope/overwatch",
    "cgroup_level": 4,
    "pids": [6120],
    "nft_table": "inet netscope_overwatch",
    "mark": "0x4e53",
    "table": 20000,
    "rule_priority": 1000,
    "attached": "late",
    "healthy": true,
    "warnings": ["name target attaches late; existing sockets are marked"],
    "consumers": ["dropship", "exitlink"],
    "policies": ["exitlink:route"],
    "generation": 3
  },
  "error": null
}
```

### `close`

Release one consumer's claim. The profile is removed only when it was the last
claim; the cgroup, nftables table, routing table, and fanotify holds are torn
down at that point. This works for both peer and persistent claims.

```json
{"id": 5, "op": "close", "profile": "overwatch", "consumer": "exitlink"}
```

```json
{
  "id": 5,
  "ok": true,
  "data": {
    "profile": "overwatch",
    "released": true,
    "removed": false,
    "consumers": ["dropship"]
  },
  "error": null
}
```

`CloseResult` fields: `profile`, `released` (the named consumer's claim was
found and released), `removed` (the profile was torn down), `consumers`
(remaining consumer ids; empty when removed).

### `resolve`

Look up a profile by id, or by the shared identity plus UID. Provide a
`profile` id, or a `target` with `target_uid`.

Either request form:

```json
{"id": 6, "op": "resolve", "profile": "overwatch"}
```

```json
{"id": 7, "op": "resolve", "target": {"kind": "name", "name": "Overwatch.exe"}, "target_uid": 1000}
```

The second form's response:

```json
{
  "id": 7,
  "ok": true,
  "data": {
    "id": "overwatch",
    "mode": "route",
    "enabled": true,
    "target": "name:Overwatch.exe",
    "cgroup": "/sys/fs/cgroup/netscope/overwatch",
    "cgroup_level": 4,
    "pids": [6120],
    "nft_table": "inet netscope_overwatch",
    "mark": "0x4e53",
    "table": 20000,
    "rule_priority": 1000,
    "attached": "late",
    "healthy": true,
    "warnings": ["name target attaches late; existing sockets are marked"],
    "consumers": ["exitlink"],
    "policies": ["exitlink:route"],
    "generation": 3
  },
  "error": null
}
```

`data` is a `ProfileStatus`. A miss is a normal error response
(`profile <id> not found` or `no profile for target`), not an empty object.
The SDK surfaces that as `ClientError::Daemon`; its `Ok(None)` corresponds
only to a `null` payload.

### `list`

All profiles, without the daemon header that `status` carries.

```json
{"id": 8, "op": "list"}
```

```json
{
  "id": 8,
  "ok": true,
  "data": [
    {
      "id": "overwatch",
      "mode": "route",
      "enabled": true,
      "target": "name:Overwatch.exe",
      "cgroup": "/sys/fs/cgroup/netscope/overwatch",
      "cgroup_level": 4,
      "pids": [6120],
      "nft_table": "inet netscope_overwatch",
      "mark": "0x4e53",
      "table": 20000,
      "rule_priority": 1000,
      "attached": "late",
      "healthy": true,
      "warnings": ["name target attaches late; existing sockets are marked"],
      "consumers": ["exitlink"],
      "policies": ["exitlink:route"],
      "generation": 3
    }
  ],
  "error": null
}
```

Disabled profiles are included. An empty daemon returns `"data": []`.

### `refresh`

Force an immediate target re-stat and attach pass instead of waiting for the
next poll interval. For a Wine target whose file changed, the fanotify mark is
moved to the new inode.

```json
{"id": 9, "op": "refresh"}
```

```json
{"id": 9, "ok": true, "data": {"updated": 1}, "error": null}
```

`updated` counts profile targets and held executables whose device/inode
identity changed during the re-stat. Attaching runs regardless of that count.
`refresh` does not repair a deleted nftables table; the daemon's health loop
does that.

### Administrative operations

The same transport carries the CLI's single-owner operations. Their responses
use `ProfileStatus` for `add`, `enable`, and `disable`, and a small object for
`remove`:

| Request | Success `data` |
|---|---|
| `{"id": 10, "op": "add", "name": "blocked", "target": {"kind": "native", "path": "/usr/bin/curl"}, "mode": {"kind": "filter", "default": "drop"}, "target_uid": 1000}` | `ProfileStatus` |
| `{"id": 11, "op": "remove", "name": "blocked"}` | `{"removed": "blocked"}` |
| `{"id": 12, "op": "enable", "name": "blocked"}` | `ProfileStatus` |
| `{"id": 13, "op": "disable", "name": "blocked"}` | `ProfileStatus` |

`add` uses `mode` (a `PolicySpec`) rather than `policy`, matching the CLI's
one-shot profile model. See the [CLI reference](cli.md#add) for the rules
around each target and policy flag; the daemon enforces the same validation.

## Rust SDK: `netscope-client`

The crate lives at `crates/netscope-client` in this repository. It wraps the
socket, assigns request ids, checks response ids, and enforces the 10-second
timeouts.

```toml
[dependencies]
netscope-client = { path = "../netscope/crates/netscope-client" }
```

```rust
use netscope_client::{Client, ClientError, Hold, PolicySpec};

fn main() -> Result<(), ClientError> {
    // One Client owns one socket connection. Keep it alive for a peer hold.
    let mut client = Client::connect()?;

    let handle = client.open_process(
        "exitlink",
        "Overwatch.exe",
        1000,
        Hold::Peer,
    )?;
    println!("profile {} ({})", handle.profile, handle.state);

    client.set_policy(
        &handle.profile,
        "exitlink",
        PolicySpec::Route {
            interface: "tun0".to_string(),
            gateway: None,
            gateway6: None,
            include_lan: false,
            allow_ipv6: false,
            udp_only: true,
            except_ports: vec![53],
            except_sports: Vec::new(),
            except: Vec::new(),
        },
    )?;

    client.close_scope(&handle.profile, "exitlink")?;
    Ok(())
}
```

Public API:

| Method | Purpose |
|---|---|
| `Client::connect()` | Connect to `/run/netscope/control.sock`. |
| `Client::connect_at(path)` | Connect to a non-default socket. |
| `Client::is_available()` / `is_available_at(path)` | Probe without keeping a client. |
| `status()` | `StatusData` for the daemon and every profile. |
| `open_scope(OpenScope)` | Escape hatch for all `open` fields. |
| `open_process(consumer, process_name, target_uid, hold)` | Create or join a name scope. |
| `set_policy(profile, consumer, PolicySpec)` | Replace a consumer's policy. |
| `clear_policy(profile, consumer)` | Remove a consumer's policy, keep its claim. |
| `close_scope(profile, consumer)` | Release a claim; removes the profile when last. |
| `resolve(profile, target, target_uid)` | Find a profile as `Option<ProfileStatus>`; a miss is `ClientError::Daemon`. |
| `list()` | Every `ProfileStatus`. |
| `refresh()` | Force a re-stat and attach pass. |
| `raw_request(RequestOp)` | Send any operation and get the raw `data`. |

`ClientError` distinguishes `Unavailable` (missing socket, nothing listening,
or the daemon closed without replying), `Permission` (the socket rejected the
connection), `Daemon` (the daemon replied `ok: false`, message preserved),
`Protocol` (bad JSON, oversized response, or mismatched id), and `Io`.

Re-exports include `Hold`, `TargetSpec`, `PolicySpec`, `FilterDefault`,
`OpenScope`, `ScopeHandle`, `CloseResult`, `StatusData`, `ProfileStatus`, and
`RequestOp`.

## Python client

A complete standalone client. It opens one connection per request, which is
fine for inspection and one-shot calls; keep one socket open if you use a peer
hold.

```python
import json
import socket

SOCKET = "/run/netscope/control.sock"

def call(op, **args):
    request = {"id": 1, "op": op, **args}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SOCKET)
        sock.sendall(json.dumps(request).encode("utf-8") + b"\n")
        reply = sock.makefile("rb").readline()
    response = json.loads(reply)
    if not response["ok"]:
        raise RuntimeError(response["error"])
    return response["data"]

status = call("status")
print(status["daemon_version"], status["api_version"])
handle = call(
    "open",
    consumer="exitlink",
    target={"kind": "name", "name": "Overwatch.exe"},
    target_uid=1000,
    name="overwatch",
    hold="persistent",
)
print(handle["profile"], handle["state"])
print(call("close", profile=handle["profile"], consumer="exitlink"))
```

## Go client

A complete program using `net.Dial("unix", …)`. `json.Encoder.Encode` appends
the newline the protocol requires.

```go
package main

import (
	"encoding/json"
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("unix", "/run/netscope/control.sock")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	req := map[string]any{"id": 1, "op": "status"}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		panic(err)
	}

	var resp struct {
		ID    uint64          `json:"id"`
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error *string         `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		panic(err)
	}
	if !resp.OK {
		panic(*resp.Error)
	}
	fmt.Println(string(resp.Data))
}
```

## C client

POSIX sockets only, no external library. Compile with `cc client.c -o client`.

```c
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int call(const char *request, char *reply, size_t reply_len)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
             "/run/netscope/control.sock");

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (send(fd, request, strlen(request), 0) < 0) {
        close(fd);
        return -1;
    }

    size_t used = 0;
    while (used + 1 < reply_len) {
        ssize_t n = recv(fd, reply + used, reply_len - used - 1, 0);
        if (n <= 0)
            break;
        used += (size_t)n;
        if (reply[used - 1] == '\n')
            break;
    }
    reply[used] = '\0';
    close(fd);
    return (int)used;
}

int main(void)
{
    char reply[4096];
    const char *request = "{\"id\":1,\"op\":\"status\"}\n";

    if (call(request, reply, sizeof(reply)) <= 0) {
        fprintf(stderr, "netscoped not reachable\n");
        return 1;
    }
    fputs(reply, stdout);
    return 0;
}
```

## Shell

The CLI is the shortest path for one-shot calls:

```sh
netscope status --json
netscope list --json
netscope refresh

sudo netscope --uid "$(id -u)" open --consumer exitlink --name overwatch \
  --process Overwatch.exe --route tun0
sudo netscope policy overwatch --consumer exitlink --route tun0 --udp --except-port 53
sudo netscope close overwatch --consumer exitlink
```

Raw NDJSON with `socat`:

```sh
printf '%s\n' '{"id":1,"op":"status"}' | socat - UNIX-CONNECT:/run/netscope/control.sock
```

Open a scope, read its response, then close it:

```sh
printf '%s\n' '{"id":1,"op":"open","consumer":"exitlink","target":{"kind":"name","name":"Overwatch.exe"},"target_uid":1000,"name":"overwatch","hold":"persistent"}' \
  | socat - UNIX-CONNECT:/run/netscope/control.sock
printf '%s\n' '{"id":2,"op":"close","profile":"overwatch","consumer":"exitlink"}' \
  | socat - UNIX-CONNECT:/run/netscope/control.sock
```

Each `socat` invocation is a fresh connection. A `hold: "peer"` claim from one
of these one-liners is released as soon as `socat` exits, so use `persistent`
or keep a single connection open for the scope's life.

## Permissions

The socket is root-owned and group-accessible. The daemon derives the
caller's UID from the kernel (`SO_PEERCRED`), not from the request:

- A non-root caller must pass its own UID as `target_uid`; naming another
  user's UID is rejected.
- Mutating an existing profile requires root or the profile's owner.
- A consumer can only set or clear a policy after it has called `open`.
- Root may act on any profile.

For the deployment model, see [Security](security.md). For the CLI rules that
mirror these checks, see the [CLI reference](cli.md).
