#!/usr/bin/env bash
# repro-cpu-throttle.sh: check whether CPU-quota'd tasks can be killed promptly.
#
# Found during Phase 2 on kernel 7.0.0-38-generic: a busy loop in a cgroup
# with cpu.max set sometimes stops receiving CPU entirely (cpu.stat usage_usec
# frozen while nr_throttled keeps rising), so a pending SIGKILL is not
# delivered for many seconds. This script reproduces it WITHOUT minibox,
# using only systemd-run, to show it is a kernel/systemd issue.
#
# Safe to run: each loop is capped at 25% of one CPU, and the EXIT trap
# removes the quota so any stuck loop can die, then kills it.
#
# Usage: scripts/repro-cpu-throttle.sh [trials] [seconds-before-kill]

set -u
trials=${1:-3}
run_for=${2:-3}
units=()
pids=()

cleanup() {
    local i
    for i in "${!units[@]}"; do
        # Lifting the quota lets a throttled task run again and act on
        # the SIGKILL that is already pending.
        systemctl --user set-property --runtime "${units[$i]}" CPUQuota= 2>/dev/null
        kill -KILL "${pids[$i]}" 2>/dev/null
    done
}
trap cleanup EXIT

alive() { [ -e "/proc/$1" ] && [ "$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)" != Z ]; }

echo "kernel $(uname -r): $trials trial(s), SIGKILL after ${run_for}s under CPUQuota=25%"
stuck=0
for t in $(seq "$trials"); do
    unit="minibox-throttle-repro-$$-$t"
    systemd-run --user --quiet --unit="$unit" -p CPUQuota=25% -- sh -c 'while :; do :; done'
    pid=$(systemctl --user show -p MainPID --value "$unit")
    units+=("$unit.service"); pids+=("$pid")
    sleep "$run_for"

    cg=/sys/fs/cgroup$(cut -d: -f3 "/proc/$pid/cgroup")
    before=$(awk '/usage_usec/{print $2}' "$cg/cpu.stat")
    start=$(date +%s%N)
    kill -KILL "$pid"
    for _ in $(seq 100); do alive "$pid" || break; sleep 0.1; done   # wait up to 10s
    ms=$(( ($(date +%s%N) - start) / 1000000 ))

    if alive "$pid"; then
        after=$(awk '/usage_usec/{print $2}' "$cg/cpu.stat" 2>/dev/null)
        echo "  trial $t: STILL ALIVE ${ms}ms after SIGKILL (usage_usec $before -> $after)"
        stuck=$((stuck + 1))
    else
        echo "  trial $t: killed after ${ms}ms"
    fi
done
echo "$stuck of $trials trial(s) ignored SIGKILL for >10s"
[ "$stuck" -eq 0 ]
