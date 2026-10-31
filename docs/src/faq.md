# FAQ

## Why does netscope need root?

`netscoped` creates cgroups under `/sys/fs/cgroup`, opens a fanotify permission group, and invokes `nft` and `ip`. All of those require privilege. The CLI itself is unprivileged and talks to the daemon over a Unix socket; only the daemon is root.

If you do not want a root daemon, do not run netscope. There is no unprivileged mode.

## Why not eBPF?

eBPF could implement similar filtering, but it adds a verifier, program loading, kernel-version-specific bytecode, and a larger privileged surface. cgroup v2 plus nftables already provides a stable socket-to-cgroup match on the kernels netscope targets, with rules that are easy to inspect using `nft list`. netscope loads no BPF program and no kernel module.

This is a scope decision, not a claim that eBPF is unsuitable for every workload.

## Why kernel 5.13?

5.13 is the first kernel with `FAN_OPEN_EXEC_PERM`, the fanotify permission event that lets the daemon hold an `exec` while it moves the process into the profile cgroup. Without it, only late attachment is possible and the first sockets can escape. netscope targets 5.13 and newer rather than shipping a weaker guarantee on older kernels.

## Is there a wrapper?

No. You launch the application normally. There is no `netscope run -- app`, no `LD_PRELOAD`, and no proxy environment variable to set. Selection happens at `exec` through fanotify, or by polling if fanotify is unavailable.

## What about applications that are already running?

They are attached late by the poller, if they match. Sockets that were opened before the attach keep their original cgroup and are **not** affected. Restart the application for full coverage. The CLI warns you when it attaches to an already-running app.

## Does netscope affect the whole system?

No. It scopes selected applications, one profile at a time, up to 32 profiles. Other processes keep their normal networking. There is no system-wide mode.

If you need system-wide filtering or routing, use a firewall, a VPN client with a kill switch, or a network namespace. netscope is not a replacement for those.

## Does it hide my IP or encrypt traffic?

No. Filter mode accepts or drops packets. Route mode sends marked packets to an interface you configured; it does not create or encrypt a tunnel. Your VPN or tunnel client provides encryption. netscope does not change your source address by itself.

## Does it work with WireGuard, OpenVPN, or another VPN?

Route mode works with any interface that exists on the host, such as `wg0` or `tun0`, as long as the interface can carry the traffic and has a route. netscope does not configure the VPN, its DNS, or its kill switch.

Filter mode is independent of the VPN; it filters destinations regardless of the route they would take.

## Does it survive a reboot?

Profiles are stored in `/var/lib/netscope/state.json`, so definitions survive a reboot. The host rules do not; the daemon recreates them when it starts. Enable `netscoped` at boot:

```sh
sudo systemctl enable netscoped
```

An application that starts before the daemon is attached late, and its early sockets are not covered. Start the daemon early, or restart the app after the daemon is up.

## Can I edit a profile?

Not in v0.1.0. Remove it and add it again with the new target or mode. `enable` and `disable` toggle enforcement without changing the definition.

## Can one profile cover several applications?

No. One profile has one target: an executable or a Steam app ID. Use separate profiles, up to 32.

## Can two profiles target the same application?

Yes, but each gets its own cgroup and rules. Running the application would attach it to one of them, not both. Use one profile per application unless you have a specific reason not to.

## Does it capture or log my traffic?

No packet capture, no payload logging, no DNS logging. The daemon logs operational events such as profile changes, attachment source, nftables failures, and reconciliation results. `netscope logs` shows a bounded recent view.

## Does it support IPv6?

Filter mode supports IPv6 CIDRs and loopback. Route mode drops IPv6 by default; `--allow-ipv6` installs an IPv6 rule and route. If the tunnel does not carry IPv6, leaving it disabled is the safe choice.

## How is DNS handled?

netscope does not rewrite DNS. In filter mode, allow the resolver's address if the profile uses `--filter drop`. In route mode, the app's DNS follows the tunnel; configure DNS in the tunnel client or use a resolver reachable through it.

## Does it work with Steam games?

Yes, with `--steam <appid>`. Add the profile before launching the game and launch it through Steam. If Steam was already running, restart it so the game's process is attached before it opens sockets.

## Is it a firewall?

No. It is a per-application scoping tool built on nftables. It does not replace a firewall, and route mode is not a guaranteed kill switch. See [Security](security.md) and [Route mode](modes/route.md).

## Does it work on Windows or macOS?

No. It relies on Linux cgroup v2, fanotify, nftables, and policy routing.

## Does it work with Flatpak or Snap applications?

Not tested in v0.1.0. Sandboxed applications may run in a different cgroup or mount namespace, and the executable path you see outside the sandbox may not be the path the daemon matches. Use `netscope status` to see whether the process was attached, and report a reproducible case.

## What license is it under?

Dual-licensed under MIT OR Apache-2.0, at your option. Contributions are accepted under the same terms and require a DCO sign-off.

## Why is there no GUI or remote dashboard?

The v0.1.x scope is a CLI and a local root daemon. There is no network listener, no telemetry, and no hosted service. A remote UI would widen the privileged surface and is out of scope for now.
