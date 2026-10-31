#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
usage: uninstall.sh [--purge] [--dry-run]

Remove the netscope binaries, systemd unit, sysusers entry, and the
netscope group. Runtime rules and cgroups are cleaned up first.

  --purge     also remove /etc/netscope and /var/lib/netscope
  --dry-run   print every action without changing the system
EOF
}

PURGE=0
DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "uninstall.sh: unknown argument $arg" >&2; usage >&2; exit 2 ;;
    esac
done

fail() {
    echo "uninstall.sh: $*" >&2
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

run_ignore systemctl disable --now netscoped.service
if [ -x /usr/bin/netscope ]; then
    run_ignore /usr/bin/netscope cleanup --all
else
    echo "netscope cleanup skipped: /usr/bin/netscope not installed"
fi

run rm -f /usr/bin/netscope /usr/bin/netscoped
run rm -f /usr/lib/systemd/system/netscoped.service
run rm -f /usr/lib/sysusers.d/netscope.conf
run_ignore systemctl daemon-reload
run_ignore groupdel netscope

if [ "$PURGE" = 1 ]; then
    run rm -rf /etc/netscope /var/lib/netscope /run/netscope
    echo "purged /etc/netscope, /var/lib/netscope, and /run/netscope"
else
    echo "preserved /etc/netscope and /var/lib/netscope (use --purge to remove)"
fi

echo "uninstalled."
