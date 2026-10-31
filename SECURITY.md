# Security policy

## Reporting

Report vulnerabilities privately at <https://github.com/Qiiks/netscope/security/advisories/new>. Do not open a public issue for a vulnerability.

Include the netscope version, distribution, kernel, steps to reproduce, and whether the daemon runs under systemd or manually. A support bundle is useful after you review it:

```sh
sudo netscope support-bundle
```

## Trust boundary

`netscoped` runs as root. It creates cgroups, calls `nft` and `ip`, and reads `/proc`. It accepts JSON-lines requests only on a Unix socket owned by `root:netscope` with mode `0660`; it does not open a TCP listener or a web UI in v0.2.0.

Members of the `netscope` group may add profiles for their own UID and may manage profiles they own. Only root may manage another user's profile. The daemon validates profile names, paths, CIDRs, interfaces, and numeric ranges, and never invokes a shell.

## Scope of protection

netscope scopes traffic from processes it successfully attaches to the profile cgroup. It does not protect traffic from processes that escaped attachment, sockets opened before attachment, kernel-generated packets without a socket, or traffic forwarded on behalf of another host. See `docs/modes/route.md` for the route-mode limits.

## Disclosure

We aim to acknowledge a report within seven days. Please allow a fix and release before public disclosure.
