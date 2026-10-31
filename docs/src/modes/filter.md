# Filter mode

Filter mode accepts or drops packets from one application. On its own it does not change routing: accepted traffic follows the machine's normal routes. A shared profile that also carries a route policy sends accepted traffic through that route.

```sh
sudo netscope --uid "$(id -u)" add blocked --exe /usr/bin/curl --filter drop
```

## Defaults

`--filter` takes one value:

| Value | Behavior |
|---|---|
| `drop` | Loopback and `--allow-cidr` destinations are accepted; everything else is dropped. |
| `allow` | `--deny-cidr` destinations are dropped; everything else is accepted. |

Loopback is always accepted in `drop` mode, for both IPv4 (`127.0.0.0/8`) and IPv6 (`::1/128`). `allow` mode accepts loopback unless you deny it explicitly with a CIDR.

## Exceptions

### `--filter drop --allow-cidr`

Each `--allow-cidr` is a destination network that remains reachable. Repeat the flag for multiple networks:

```sh
sudo netscope --uid "$(id -u)" add blocked-allow \
  --exe /usr/bin/curl \
  --filter drop \
  --allow-cidr 203.0.113.10/32 \
  --allow-cidr 2001:db8::/32
```

`--allow-cidr` is only valid with `--filter drop`. It is invalid with `--filter allow`.

### `--filter allow --deny-cidr`

`allow` mode requires at least one `--deny-cidr`; without one the profile would accept everything and do nothing.

```sh
sudo netscope --uid "$(id -u)" add limited \
  --exe /usr/bin/curl \
  --filter allow \
  --deny-cidr 198.51.100.0/24
```

`--deny-cidr` is only valid with `--filter allow`. It is invalid with `--filter drop`.

CIDRs must parse as IPv4 or IPv6 networks. An invalid CIDR is rejected with exit code `2` before the profile is created.

## Evaluation order

`--filter drop` emits a negated drop per family: everything except loopback and
the `--allow-cidr` destinations is dropped, and non-IP traffic is dropped too.
An accepted packet falls through to any route policy in the same shared
profile, so a filter never silently replaces a route. `--filter allow` drops
only the `--deny-cidr` destinations and lets everything else fall through.

## What the rules match

The generated rules match sockets in the profile's cgroup and sockets carrying
the profile's firewall mark:

```text
socket cgroupv2 level 2 "netscope/<profile>"
socket mark 0x4e53
```

The second form covers a socket that existed before a late attach: the daemon
cannot move that socket into the cgroup, so it marks the socket itself. Both
rules are repeated for every filter rule. They do not match by executable name,
user, or port. All protocols and ports are covered, including TCP, UDP, QUIC,
and ICMP, as long as the packet's socket is in the cgroup or carries the mark:

- **TCP and UDP:** the socket belongs to the process, so the rule applies.
- **QUIC:** carried over UDP and treated the same way.
- **ICMP echo:** uses an ICMP socket owned by the sending process, so it is matched.

## DNS

Filter mode does not special-case DNS. In `drop` mode, name resolution fails unless the resolver's address is allowed:

```sh
sudo netscope --uid "$(id -u)" add blocked \
  --exe /usr/bin/curl \
  --filter drop \
  --allow-cidr 1.1.1.1/32 \
  --allow-cidr 1.0.0.1/32
```

If the system resolver is a local stub such as `127.0.0.53`, the query to the stub is loopback and is accepted, but the stub's own upstream query is a different process and is not filtered by this profile. Allow the real upstream resolver if the stub forwards over the network.

Host names cannot be used as exceptions. Resolve them first and allow the address or network.

## Existing connections

The filter applies to packets, not to an application's lifetime. A socket that was open before a late attach is marked with the profile's firewall mark, so its packets are matched without a restart. If a descriptor cannot be marked, the daemon logs `mark profile=... error=...` and that socket continues on its old path; restart the application to cover it.

## Changes and removal

- A consumer's policy can be replaced with `netscope policy`; `netscope add` still creates a one-shot profile owned by `netscope-cli`.
- `enable` and `disable` keep the profile and its cgroup but stop or resume enforcement.
- `remove` deletes the nftables table and the cgroup. Traffic is unfiltered immediately.

## Interaction with route mode

A shared profile can carry several filter policies and one route policy, one
policy per consumer. Filters run first; a packet dropped by any consumer is
terminal, and an accepted packet continues to the route mark. A second
filter or route consumer for the same target and target uid joins that profile
through `netscope open`; a second `netscope add` is refused. See
[Shared scopes](../shared-scopes.md).

## Examples

Drop everything except one API and its DNS resolver:

```sh
sudo netscope --uid "$(id -u)" add api-only \
  --exe /usr/bin/myapp \
  --filter drop \
  --allow-cidr 203.0.113.10/32 \
  --allow-cidr 1.1.1.1/32
```

Allow everything except a LAN subnet:

```sh
sudo netscope --uid "$(id -u)" add no-lan \
  --exe /usr/bin/myapp \
  --filter allow \
  --deny-cidr 192.168.0.0/16
```

Verify with `netscope status`, then remove with `netscope remove api-only`.
