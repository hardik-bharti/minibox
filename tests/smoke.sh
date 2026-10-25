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

echo "Phase 2: resource limits"

# Memory: a 200 MiB buffer under a 50 MiB limit is OOM-killed (SIGKILL,
# exit 137). The same command with a 20 MiB buffer runs fine. Swap is
# disabled for the container, so the hog cannot escape into swap.
set +e
out=$("$B" run --memory 50m --stats "$IMG" dd if=/dev/zero of=/dev/null bs=200M count=1 2>&1); code=$?
set -e
check "memory hog killed (exit 137)" "137" "$code"
check "OOM kill reported" "1" "$(grep -c "killed for exceeding --memory" <<<"$out")"
check "memory peak capped at 50 MiB" "memory_peak_bytes=$((50 << 20))" "$(grep -o 'memory_peak_bytes=[0-9]*' <<<"$out")"
check "small allocation under limit succeeds" "0" "$("$B" run --memory 50m "$IMG" dd if=/dev/zero of=/dev/null bs=20M count=1 >/dev/null 2>&1; echo $?)"

# Pids: a *bounded* fork bomb, a binary process tree 7 levels deep. Without a
# limit it peaks at ~380 tasks (shells + sleeps); with --pids 20 it must
# never exceed 20. It's bounded so that even if the limit failed, the test
# could not exhaust the VM.
tree='f() { if [ "$1" -eq 0 ]; then sleep 1; return; fi; f $(($1-1)) & f $(($1-1)) & wait; }; f 7'
out=$("$B" run --pids 20 --stats "$IMG" sh -c "$tree" 2>&1 || true)
check "fork tree capped at --pids 20" "pids_peak=20" "$(grep -o 'pids_peak=[0-9]*' <<<"$out")"
check "refused forks reported" "1" "$(grep -c "fork(s) refused by --pids 20" <<<"$out")"

# Input validation.
check "--pids below minimum rejected" "1" "$("$B" run --pids 3 "$IMG" true 2>/dev/null; echo $?)"
check "bad --memory rejected" "1" "$("$B" run --memory lots "$IMG" true 2>/dev/null; echo $?)"

# Cleanup: no container cgroups or minibox scopes left behind.
ucg=/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service
for _ in $(seq 20); do   # systemd removes the scope asynchronously
    left=$(find "$ucg" -type d -name supervisor 2>/dev/null | wc -l)
    [ "$left" -eq 0 ] && break
    sleep 0.1
done
check "cgroups removed after exit" "0" "$left"

# CPU: a fixed amount of work (no signals involved) should take roughly 4x
# longer at --cpus 0.25 than unlimited, and the kernel should report
# throttled periods. Timing-based, so it needs a VM whose vCPUs are scheduled
# regularly (check-env.sh warns otherwise). MINIBOX_SKIP_CPU=1 skips it.
if [ "${MINIBOX_SKIP_CPU:-0}" != 1 ]; then
    work='i=0; while [ $i -lt 400000 ]; do i=$((i+1)); done'
    t0=$(date +%s%N); "$B" run "$IMG" sh -c "$work"; t1=$(date +%s%N)
    out=$("$B" run --cpus 0.25 --stats "$IMG" sh -c "$work" 2>&1); t2=$(date +%s%N)
    ratio=$(( (t2 - t1) * 10 / (t1 - t0) ))   # x10, so 25 means 2.5x slower
    check "CPU-bound task slowed >= 2.5x at --cpus 0.25 (ratio x10=$ratio)" "yes" "$([ "$ratio" -ge 25 ] && echo yes || echo no)"
    check "kernel reports throttling" "yes" "$(grep -qE 'nr_throttled=[1-9]' <<<"$out" && echo yes || echo no)"
else
    echo "  skip CPU throttle test (MINIBOX_SKIP_CPU=1)"
fi

echo
if [ "$failures" -eq 0 ]; then echo "smoke tests passed"; else echo "$failures smoke test(s) FAILED"; exit 1; fi
