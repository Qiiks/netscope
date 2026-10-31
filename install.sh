#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
usage: install.sh [--dry-run]

Install netscope binaries, the systemd unit, the sysusers entry, and the
default configuration. Existing /etc/netscope/config.toml and
/var/lib/netscope/state.json are preserved.

  --dry-run   print every action without changing the system
EOF
}

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install.sh: unknown argument $arg" >&2; usage >&2; exit 2 ;;
    esac
done

fail() {
    echo "install.sh: $*" >&2
    exit 1
}

run() {
    if [ "$DRY_RUN" = 1 ]; then
        printf 'would: %s\n' "$*"
    else
        "$@"
    fi
}

run_ignore() {
    if [ "$DRY_RUN" = 1 ]; then
        printf 'would: %s\n' "$*"
    else
        "$@" || true
    fi
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pick() {
    local candidate
    for candidate in "$@"; do
        if [ -f "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

netscope_bin=$(pick "$here/netscope" "$here/target/release/netscope" "$here/target/debug/netscope") \
    || fail "netscope binary not found; run cargo build --release --workspace first"
netscoped_bin=$(pick "$here/netscoped" "$here/target/release/netscoped" "$here/target/debug/netscoped") \
    || fail "netscoped binary not found; run cargo build --release --workspace first"
unit_file=$(pick "$here/netscoped.service" "$here/packaging/netscoped.service") \
    || fail "netscoped.service not found"
sysusers_file=$(pick "$here/netscope.sysusers" "$here/packaging/netscope.sysusers") \
    || fail "netscope.sysusers not found"
config_file=$(pick "$here/config.toml" "$here/packaging/config.toml") \
    || fail "config.toml not found"

[ "$(uname -m)" = "x86_64" ] || fail "unsupported architecture $(uname -m); netscope v0.1.0 ships x86_64 only"

kernel=$(uname -r)
kernel_release=${kernel%%-*}
if ! printf '%s\n%s\n' "5.13" "$kernel_release" | sort -V -C; then
    fail "netscope requires Linux 5.13 or newer (found $kernel)"
fi

[ -e /sys/fs/cgroup/cgroup.controllers ] || fail "cgroup v2 is not mounted at /sys/fs/cgroup"
command -v nft >/dev/null 2>&1 || fail "nft (nftables) is required"
command -v ip >/dev/null 2>&1 || fail "ip (iproute2) is required"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"
command -v systemd-sysusers >/dev/null 2>&1 || fail "systemd-sysusers is required"

run_ignore systemctl stop netscoped.service

run install -Dm755 "$netscope_bin" /usr/bin/netscope
run install -Dm755 "$netscoped_bin" /usr/bin/netscoped
run install -Dm644 "$unit_file" /usr/lib/systemd/system/netscoped.service
run install -Dm644 "$sysusers_file" /usr/lib/sysusers.d/netscope.conf

run systemd-sysusers
run systemctl daemon-reload

if [ -e /etc/netscope/config.toml ]; then
    echo "preserved /etc/netscope/config.toml"
else
    run install -Dm644 "$config_file" /etc/netscope/config.toml
fi

run systemctl enable netscoped.service
run systemctl restart netscoped.service

cat <<'EOF'
installed. add your user to the netscope group:
  sudo usermod -aG netscope $USER
then log out and back in.
EOF
