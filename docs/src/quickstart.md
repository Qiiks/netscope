# Quick start

This walkthrough blocks one application's outbound traffic, checks that the block applies only to that application, and then removes the profile. It assumes netscope is installed and `netscoped` is running; see [Install](install.md).

All examples use `sudo netscope --uid "$(id -u)"`. The `$(id -u)` is expanded by your shell before `sudo`, so it is your user ID, not root's. If your user is in the `netscope` group and you have logged in again, you can omit both `sudo` and `--uid`.

## 1. Check the daemon

```sh
sudo systemctl status netscoped
netscope status
```

`netscope status` prints the daemon version, kernel, cgroup root, and profile table. If it exits `3`, the daemon is not reachable:

```text
netscope: daemon not running; start with: sudo systemctl start netscoped
```

Start it with `sudo systemctl start netscoped`, then retry.

## 2. Block one application

```sh
sudo netscope --uid "$(id -u)" add blocked --exe /usr/bin/curl --filter drop
```

This creates a profile named `blocked` for `/usr/bin/curl` with a filter whose default action is `drop`. The executable path is resolved from your current directory, so relative paths work, but an absolute path is clearer.

Test it:

```sh
curl --max-time 3 https://example.com
```

The request fails because every non-loopback destination from `curl` is dropped. Loopback is still accepted in `drop` mode; to see it working, run a local server in another terminal and fetch it:

```sh
python3 -m http.server 8080
curl --max-time 3 http://127.0.0.1:8080/
```

## 3. Inspect the profile

```sh
netscope list
sudo netscope status
```

`list` shows `NAME`, `MODE`, `ENABLED`, `TARGET`, `ATTACHED`, and `PIDS` for every profile, including disabled ones. `status` adds the daemon and cgroup header. A process that was started before the profile was added appears as `late`; a process caught by the exec hook appears as `pre-exec`.

Short-lived commands are usually gone before you look, so `PIDS` may be empty even though the block applied.

## 4. Add a narrow exception

Replace the profile with one that allows a single address:

```sh
sudo netscope --uid "$(id -u)" remove blocked
sudo netscope --uid "$(id -u)" add blocked --exe /usr/bin/curl --filter drop --allow-cidr 1.1.1.1/32
curl --max-time 5 https://1.1.1.1/
```

With this profile, `https://1.1.1.1/` is allowed and every other destination is still dropped. Exceptions are destination CIDRs, not host names or ports. If the TLS certificate check fails on your system, use `curl -k` for this connectivity test only.

## 5. Select an app at launch

The point of the exec hook is that nothing wraps the application. For example:

```sh
sudo netscope --uid "$(id -u)" add browser --exe /usr/bin/firefox --filter allow --deny-cidr 192.168.0.0/16
firefox
```

Start `firefox` normally, from the desktop or a shell. The daemon catches the `exec`, places the process in the `netscope/browser` cgroup before its first socket, and nftables matches the cgroup. In this example the browser keeps internet access but cannot reach the `192.168.0.0/16` LAN. If the app is already running when you add the profile, restart it for full coverage.

## 6. Route instead of filter

Route mode requires a tunnel interface that already exists, such as `tun0` from WireGuard or OpenVPN:

```sh
sudo netscope --uid "$(id -u)" add routed --exe /usr/bin/curl --route tun0
curl --max-time 5 https://example.com
```

Traffic from `curl` is marked and looked up in netscope's dedicated routing table. LAN destinations bypass the tunnel by default. To send LAN traffic through the tunnel too, add `--include-lan`:

```sh
sudo netscope --uid "$(id -u)" remove routed
sudo netscope --uid "$(id -u)" add routed --exe /usr/bin/curl --route tun0 --include-lan
```

See [Route mode](modes/route.md) for the blackhole fallback and IPv6 behavior.

## 7. Run diagnostics

```sh
sudo netscope doctor
```

`doctor` exits `0` when every check passes and `1` when any fails. Run it as root (`sudo netscope doctor`); without root the `root` check fails and doctor exits `1`. Add `--json` for machine-readable output. If it fails, see [Troubleshooting](troubleshooting.md).

## 8. Clean up

```sh
sudo netscope remove blocked
sudo netscope remove browser
sudo netscope remove routed
```

`remove` deletes the profile's nftables table, routing rules, routes, and cgroup. Removing a profile does not stop the application; traffic returns to normal routing immediately.
