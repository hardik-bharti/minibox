#!/usr/bin/env bash
# smoke.sh: end-to-end checks that need the real VM, not just `go test`.
#
# Each check runs real containers through bin/minibox and asserts one
# isolation property. Run via `make smoke` (which builds first).

set -euo pipefail
cd "$(dirname "$0")/.."

B=./bin/minibox
IMG=images/alpine
failures=0

ok()   { printf '  ok   %s\n' "$1"; }
bad()  { printf '  FAIL %s\n       %s\n' "$1" "$2"; failures=$((failures + 1)); }
# check NAME EXPECTED ACTUAL
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected '$2', got '$3'"; fi; }

# Use a throwaway state root so we can assert it is left empty.
export MINIBOX_ROOT
MINIBOX_ROOT=$(mktemp -d)
trap 'rm -rf "$MINIBOX_ROOT"' EXIT

box() { "$B" run "$IMG" "$@"; }

echo "Phase 0: setup"
for s in scripts/*.sh tests/*.sh; do bash -n "$s"; done
ok "all shell scripts parse"
scripts/check-env.sh >/dev/null
ok "check-env.sh reports no failures"
if [ ! -x "$IMG/bin/busybox" ]; then
    echo "  FAIL $IMG missing; run 'make image' first" >&2
    exit 1
fi
ok "Alpine image present"

echo "Phase 1: isolation"

# Every namespace we asked for must differ from the host's. The
# /proc/<pid>/ns/* links name a namespace by its inode number.
for ns in user mnt pid uts ipc; do
    inside=$(box readlink /proc/self/ns/$ns)
    outside=$(readlink /proc/self/ns/$ns)
    if [ "$inside" != "$outside" ]; then ok "new $ns namespace ($inside)"; else bad "new $ns namespace" "same as host: $inside"; fi
done
# We did not ask for a network namespace yet (that comes in Phase 3).
check "network namespace shared with host (until Phase 3)" "$(readlink /proc/self/ns/net)" "$(box readlink /proc/self/ns/net)"

# User namespace: root inside, our UID outside, and only that one mapping.
check "uid 0 inside container" "0" "$(box id -u)"
check "uid_map maps only container 0 -> our uid" "0 $(id -u) 1" "$(box cat /proc/self/uid_map | tr -s ' ' | sed 's/^ //')"

# PID namespace: the command is PID 1 and host processes are invisible.
check "command runs as PID 1" "1" "$(box sh -c 'echo $$')"
check "/proc/1 is our command, not host init" "cat" "$(box cat /proc/1/comm)"
check "host processes invisible (no systemd)" "0" "$(box sh -c 'cat /proc/[0-9]*/comm' | grep -c systemd || true)"

# UTS namespace: hostname is ours, and the host's is unchanged.
host_before=$(hostname)
check "--hostname sets container hostname" "box1" "$("$B" run --hostname box1 "$IMG" hostname)"
check "host hostname unchanged" "$host_before" "$(hostname)"

# Mount namespace + pivot_root: the host filesystem is gone, not just hidden.
check "host home dir not visible" "missing" "$(box sh -c "[ -e $HOME ] && echo visible || echo missing")"
check "old root fully detached" "missing" "$(box sh -c '[ -e /.oldroot ] && echo visible || echo missing')"
check "root is overlayfs" "overlay" "$(box sh -c 'grep " / " /proc/mounts | cut -d" " -f3')"
check "fresh /proc mounted" "proc" "$(box sh -c 'grep " /proc " /proc/mounts | cut -d" " -f3')"
check "/dev/null usable" "ok" "$(box sh -c 'echo hi > /dev/null && echo ok')"

# overlayfs: writes and deletes stay in the per-container upper layer.
box sh -c 'echo x > /etc/smoke-file; rm /etc/motd; echo y >> /etc/hostname' >/dev/null
check "new file did not reach the image" "no" "$([ -e $IMG/etc/smoke-file ] && echo yes || echo no)"
check "deleted file still in the image" "yes" "$([ -e $IMG/etc/motd ] && echo yes || echo no)"
check "containers do not share writes" "missing" "$(box sh -c '[ -e /etc/smoke-file ] && echo seen || echo missing')"

# Exit status and stdin pass through.
set +e; box sh -c 'exit 42'; code=$?; set -e
check "exit code propagated" "42" "$code"
check "stdin passed through" "hello" "$(echo hello | box cat)"

# Cleanup: no state dirs left, no overlay mounts visible on the host.
check "state dirs removed after exit" "0" "$(find "$MINIBOX_ROOT" -mindepth 1 | wc -l)"
check "no overlay mounts leaked to host" "0" "$(grep -c " overlay " /proc/self/mountinfo || true)"

echo
if [ "$failures" -eq 0 ]; then echo "smoke tests passed"; else echo "$failures smoke test(s) FAILED"; exit 1; fi
