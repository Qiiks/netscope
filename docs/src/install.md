# Install

netscope is alpha software for Linux. It needs a unified cgroup v2 hierarchy, nftables, iproute2, systemd, and kernel **5.13 or newer** for the fanotify exec hook.

## Requirements

| Requirement | Check | Notes |
|---|---|---|
| Linux kernel 5.13+ | `uname -r` | 5.13 is the first kernel with `FAN_OPEN_EXEC_PERM`. Older kernels cannot hold an `exec` until attachment. |
| cgroup v2 (unified) | `stat -fc %T /sys/fs/cgroup` prints `cgroup2fs` | Hybrid or v1-only systems are unsupported. |
| nftables | `nft --version` | Used for the per-profile table. |
| iproute2 | `ip -V` | Used for policy routing rules and the route-mode blackhole. |
| systemd | `systemctl --version` | Runs and supervises `netscoped`. |
| zstd | `zstd --version` | Only needed to extract the release tarball. |

Check the kernel and cgroup mode before installing:

```sh
uname -r
stat -fc %T /sys/fs/cgroup
```

`cgroup2fs` is required. If the command prints `tmpfs`, the system is still on cgroup v1.

## Choose a channel

| Channel | Installs | Unit and config | Best for |
|---|---|---|---|
| AUR `netscope-bin` | Binaries | Yes, via the package | Arch Linux and CachyOS |
| Release tarball | Binaries, unit, sysusers, config, install scripts | Yes, via `install.sh` | Any supported distro |
| Source build | Binaries from `target/release` | Yes, via `install.sh` | Development and ARM builds |
| `cargo install --git` | Binaries only | No | Advanced users who already have the system files |

The unit, the `netscope` group definition, and `/etc/netscope/config.toml` are **not** installed by Cargo. The systemd unit executes `/usr/bin/netscoped`, so a Cargo-only install does not start as a service without extra work.

## AUR (Arch Linux, CachyOS)

After the package is published:

```sh
yay -S netscope-bin
sudo systemctl enable --now netscoped
sudo usermod -aG netscope "$USER"
```

Log out and back in so the group membership applies. `paru -S netscope-bin` is equivalent.

## Release tarball

Download `netscope-v0.2.0-x86_64-linux.tar.zst` from the [v0.2.0 release](https://github.com/Qiiks/netscope/releases/tag/v0.2.0). Verify it against the published checksum:

```sh
curl -fsSLO https://github.com/Qiiks/netscope/releases/download/v0.2.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Then extract and run the included installer:

```sh
tar --zstd -xf netscope-v0.2.0-x86_64-linux.tar.zst
cd netscope-v0.2.0-x86_64-linux
sudo ./install.sh
sudo usermod -aG netscope "$USER"
```

Preview every change without touching the system with `sudo ./install.sh --dry-run`.

`install.sh` checks the architecture, kernel, cgroup mode, and required tools, then:

- installs `netscope` and `netscoped` to `/usr/bin`;
- installs the unit to `/usr/lib/systemd/system/netscoped.service`;
- installs the sysusers entry to `/usr/lib/sysusers.d/netscope.conf` and creates the `netscope` group;
- installs `/etc/netscope/config.toml` only if it does not already exist;
- enables and restarts `netscoped`.

Log out and back in after `usermod`.

## Build from source

```sh
cargo build --release --workspace
sudo ./install.sh
sudo usermod -aG netscope "$USER"
```

`install.sh` prefers binaries in the repository root, then `target/release`, then `target/debug`. It finds the unit and config in `packaging/` when they are not next to the script.

## Cargo

```sh
cargo install --git https://github.com/Qiiks/netscope --tag v0.2.0 --locked netscope-cli netscope-daemon
```

This installs the two binaries into `~/.cargo/bin` and nothing else. To run the service, the unit expects them at `/usr/bin`:

```sh
sudo install -Dm755 ~/.cargo/bin/netscope /usr/bin/netscope
sudo install -Dm755 ~/.cargo/bin/netscoped /usr/bin/netscoped
```

Then install `netscoped.service`, `netscope.conf`, and `config.toml` from the tarball or repository as `install.sh` does, or skip the service and run `sudo netscoped --foreground` manually for development.

## Verify

```sh
netscope --version
sudo netscope doctor
```

`doctor` exits `0` when every check passes and exits `1` when any check fails. It does not require any profile to exist. A non-root run fails the `root` check, so use `sudo netscope doctor` for a clean and complete report. If it reports a failure, see [Troubleshooting](troubleshooting.md).

Run a first profile from [Quick start](quickstart.md).

## Upgrade

- **AUR:** `yay -Syu netscope-bin` (or `paru -Syu netscope-bin`), then `sudo systemctl restart netscoped`.
- **Tarball or source:** unpack or rebuild, then `sudo ./install.sh` again. The installer stops the old daemon, replaces the binaries and unit, preserves `/etc/netscope/config.toml` and `/var/lib/netscope/state.json`, and restarts the service.
- **Cargo:** rerun the `cargo install` command and copy the binaries to `/usr/bin`, then `sudo systemctl restart netscoped`.

Profiles live in `/var/lib/netscope/state.json` and survive upgrades. The state format has a version field; a newer daemon rejects a state it cannot read instead of guessing.

## Uninstall

- **AUR:** `yay -Rns netscope-bin` (or `paru -Rns netscope-bin`).
- **Tarball or source:** `sudo ./uninstall.sh` from the extracted release or repository.

`uninstall.sh` stops and disables the service, runs `netscope cleanup --all`, removes the binaries, unit, and sysusers entry, and removes the `netscope` group. It preserves `/etc/netscope` and `/var/lib/netscope` unless you pass `--purge`:

```sh
sudo ./uninstall.sh --purge
```

Preview with `sudo ./uninstall.sh --dry-run`.

Do not run `uninstall.sh` for an AUR install; it would delete files owned by the package manager. Remove the package instead, then optionally `sudo rm -rf /etc/netscope /var/lib/netscope` to clear state.

If a process was still attached when the daemon exited, remove the leftover cgroup or reboot. `cleanup --all` removes netscope's profile cgroups when it can.
