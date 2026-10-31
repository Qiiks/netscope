# Distro notes

netscope needs a modern kernel, unified cgroup v2, nftables, iproute2, and systemd. These notes describe what usually works. The project's CI runs on Ubuntu 24.04; the AUR package and the release tarball are the only packaged channels in v0.1.0, and the release binary is x86_64.

## Kernel configuration

These kernel options are easy to miss on custom kernels:

```sh
grep -E 'CONFIG_(FANOTIFY|FANOTIFY_ACCESS_PERMISSIONS|NFT_SOCKET)=' "/boot/config-$(uname -r)"
```

If your kernel exposes `/proc/config.gz` instead, use `zgrep` on it.

- `CONFIG_FANOTIFY` and `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` are required for pre-exec attachment.
- `CONFIG_NFT_SOCKET` is required for the `socket cgroupv2` match.

If `NFT_SOCKET` is missing, filter and route rules cannot match the profile cgroup. If fanotify permission events are missing, only late attachment is possible and `doctor` reports it.

## Arch Linux and CachyOS

Use the AUR package:

```sh
yay -S netscope-bin
sudo systemctl enable --now netscoped
sudo usermod -aG netscope "$USER"
```

`nftables` and `iproute2` are normally installed; install them if `doctor` reports them missing. If `doctor` reports a missing fanotify permission event, check the kernel options above.

## Fedora

Fedora has cgroup v2 by default, a recent kernel, nftables, and systemd. There is no official package in v0.1.0; install the [release tarball](install.md#release-tarball).

With SELinux enforcing, a denial can block fanotify permission events or writes under `/sys/fs/cgroup`. Check the audit log before changing policy:

```sh
sudo ausearch -m avc -ts recent
journalctl -u netscoped -n 50 --no-pager
```

Report a denial that reproduces with the shipped unit. Do not disable SELinux globally to work around it.

## Debian and Ubuntu

- **Debian 12 (bookworm):** kernel 6.1, cgroup v2 by default. Works with the tarball.
- **Ubuntu 22.04 and newer:** kernel 5.15 or newer, cgroup v2 by default. Works with the tarball.
- **Debian 11:** kernel 5.10 is too old for pre-exec attachment. Upgrade the kernel or use a newer release.
- **Ubuntu 20.04:** kernel 5.4 is too old. Upgrade.

Use the tarball; there is no Debian package in v0.1.0.

## openSUSE Tumbleweed

Recent kernels and cgroup v2 are standard, and firewalld uses the nftables backend. Install the tarball. If a firewall frontend flushes unmanaged tables on reload, the daemon's health loop recreates netscope's tables within about ten seconds; a frontend that removes them continuously is a configuration conflict worth reporting.

## RHEL and compatible distributions

RHEL 9 and compatible rebuilds ship kernel 5.14 or newer with cgroup v2 and nftables. Install the tarball. Older RHEL 8 kernels are too old.

## NixOS

There is no NixOS module or package in v0.1.0. The tarball can be installed manually, but the unit and sysusers file are not declarative. A proper module would need to express the group, unit, config, and state directory; it is not included yet.

## Alpine and other non-systemd distributions

Unsupported. netscope's service management, socket directory, and state directory assume systemd. The binaries may run under another supervisor, but that path is not tested.

## Containers and WSL

- **Containers:** unsupported. netscope needs to create cgroups on the host and match the host cgroup hierarchy. Running it inside a container requires a privileged container with the host cgroup namespace, which defeats most of the isolation the container provides.
- **WSL2:** unsupported. The WSL kernel and init may not expose fanotify permission events or the cgroup hierarchy the same way a normal systemd host does.

## 32-bit and ARM

The v0.1.0 release tarball is x86_64 only, and `install.sh` rejects other architectures. The workspace can be built from source on other architectures, but the installer will not run there; copy the binaries, unit, sysusers entry, and config into place manually. The kernel features, not the CPU, determine whether the result works.

## Firewall coexistence

netscope adds its own `inet` tables named `netscope_filter_*` and `netscope_route_*`, plus `ip rule` entries and tables in the `20000`–`20031` range. It does not modify your existing firewall tables or the main routing table.

If another tool flushes all nftables tables or all routing rules, profiles break until the daemon's health loop recreates them, within about ten seconds. If the other tool removes them continuously, the two tools are incompatible on that host.
