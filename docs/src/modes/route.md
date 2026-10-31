# Route mode

Route mode sends one application's traffic through an existing tunnel interface. It uses a firewall mark and a dedicated routing table; it does not create the tunnel, configure the interface, or manage WireGuard, OpenVPN, or any other VPN.

```sh
sudo netscope --uid "$(id -u)" add routed --exe /usr/bin/curl --route tun0
```

The interface must already exist and be up. If it does not, the daemon fails to apply the profile and the CLI exits `1`.

## Options

| Option | Meaning |
|---|---|
| `--route <iface>` | Interface for the default route, for example `tun0` or `wg0`. Required. |
| `--gateway <ipv4>` | IPv4 next hop. Optional when the interface is point-to-point. |
| `--gateway6 <ipv6>` | IPv6 next hop. Only valid with `--allow-ipv6`. |
| `--include-lan` | Route LAN destinations through the tunnel instead of bypassing them. |
| `--allow-ipv6` | Carry IPv6 through the profile. Without it, all IPv6 from the profile is dropped. |

`--gateway` and `--gateway6` are mutually exclusive with the wrong family: `--gateway6` requires `--allow-ipv6`, and `--gateway` is IPv4 only.

## What gets routed

The nftables chain for a route profile:

1. accepts loopback (`127.0.0.0/8`, `::1/128`);
2. unless `--include-lan`, accepts the LAN and link-local ranges listed below;
3. unless `--allow-ipv6`, drops all IPv6;
4. sets the profile mark on everything left.

The mark is then matched by an `ip rule`:

```text
fwmark 0x4e53 table 20000 pref 1000
```

The table contains two defaults:

| Route | Metric | Effect |
|---|---|---|
| `default dev <iface> [via <gateway>]` | 100 | Used while the interface has a usable route. |
| `blackhole default` | 1000 | Used when the real route is gone, so traffic fails instead of falling back to the main table. |

The mark and table values come from the profile index. Table `20000` and mark `0x4e53` are the first profile; the next profile uses `20001` and `0x4e54`, up to 32 profiles.

## LAN bypass

By default — `include_lan = false` — route mode bypasses the tunnel for local networks. This keeps printers, game consoles, local services, and router administration reachable while the app's internet traffic is routed.

The bypass list is fixed:

| Family | Bypassed destinations |
|---|---|
| IPv4 | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `224.0.0.0/4` |
| IPv6 | `fc00::/7`, `fe80::/10`, `ff00::/8` |

`--include-lan` (`include_lan = true`) removes this bypass, so traffic to those ranges is marked and routed through the tunnel. Use it when the tunnel carries the LAN (for example a remote-access VPN that reaches a home network) and the application must use it.

Ranges outside this list, such as CGNAT `100.64.0.0/10`, are not bypassed. They follow the profile's default route.

## IPv6

The default is conservative: `allow_ipv6: false` drops every IPv6 packet from the profile, including link-local traffic that would otherwise bypass the tunnel. This avoids a dual-stack leak when the tunnel carries only IPv4.

To carry IPv6:

```sh
sudo netscope --uid "$(id -u)" add routed6 \
  --exe /usr/bin/curl \
  --route tun0 \
  --allow-ipv6 \
  --gateway6 2001:db8::1
```

With `--allow-ipv6`, the daemon also installs an IPv6 policy rule and an IPv6 default route in the same table. If the IPv6 route cannot be installed, the add fails and the profile is not left applied. If the interface later loses that route, the IPv6 blackhole matches and the traffic fails instead of using the main table. `--gateway6` is optional for point-to-point interfaces.

## Fail-closed while active, fail-open on removal

The blackhole protects traffic while the profile is active and the tunnel goes down: the real default route disappears, the blackhole at metric 1000 matches, and the packet is rejected.

It is **not** a system-wide kill switch, and it is not designed to survive the daemon being removed:

- `netscope disable` stops enforcement for that profile.
- `netscope remove` deletes the nftables table, the policy rule, and the routes. Marked traffic then falls through to the main table.
- A clean `systemctl stop netscoped` removes the daemon's host state, and manual removal of the table has the same result: the guarantee ends and normal routing resumes.
- A reboot clears the rules.
- If the daemon is killed without cleanup, the installed rules can remain. A restart reconciles and re-applies them for enabled profiles; to remove them, stop the daemon and run `sudo netscope cleanup --all`. Until they are removed, the blackhole still applies.

In short: daemon death and table removal are **fail-open once the rules are gone**. The blackhole is a property of the installed rules, not of the daemon's liveness.

Treat route mode as leak protection for the selected application while netscope is running, not as a firewall that prevents all leaks on the machine. If you need a hard kill switch, enforce it in the tunnel configuration or with a separate firewall policy.

## DNS

netscope does not configure DNS. The application's DNS queries are routed like its other UDP traffic through the tunnel. If the tunnel does not carry DNS or does not push a resolver, name resolution fails even though the interface is up. Configure DNS in the tunnel client or use a resolver reachable through the tunnel.

Queries sent to a local stub resolver are delivered over loopback and are therefore accepted before the mark. The stub's own upstream queries belong to the stub process and are routed by that process, not by this profile.

## Existing connections

A TCP connection that was established before the process was attached keeps its original route. It is not re-routed. Restart the application after adding the profile so every connection is marked.

## Inspect the routing state

```sh
ip rule show
ip route show table 20000
nft list table inet netscope_route_routed
```

Mark and table are allocated by profile index: the first profile uses mark `0x4e53` and table `20000`, and each additional profile takes the next free index. `netscope status --json` reports each profile's `mark`, `table`, and `nft_table`; `ip rule show` maps a mark to its table.

## Removing a route profile

```sh
sudo netscope remove routed
```

The daemon deletes the IPv4 (and, when enabled, IPv6) policy rule, flushes the table, and removes the nftables table. The application keeps running and returns to the main routing table. Restart it if you need its existing connections to follow the new path.
