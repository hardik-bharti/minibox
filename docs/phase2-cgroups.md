# Phase 2: Resource limits (cgroups v2)

Code: `internal/cgroups/` (limits, cgroup creation, stats) and the re-exec in
`cmd/minibox/run.go` (`reexecInScope`).

## Flags

| Flag | cgroup file | Meaning |
|------|-------------|---------|
| `--memory 64m` | `memory.max`, `memory.swap.max=0` | RAM cap; exceeding it gets the process OOM-killed |
| `--cpus 0.5` | `cpu.max` = `50000 100000` | At most 50 ms of CPU time per 100 ms period |
| `--pids 50` | `pids.max` | Max tasks (processes **and threads**); fork/clone fails beyond it |
| `--stats` | reads `cpu.stat`, `memory.peak`, `memory.events`, `pids.peak`, `pids.events` | Prints usage on exit |

## How a container gets its cgroup

```mermaid
flowchart TD
    A["minibox run --memory 64m ...<br/>(in session-1.scope, owned by root)"] -->|"not delegated: exec"| B["systemd-run --user --scope -p Delegate=yes<br/>-- minibox run --memory 64m ..."]
    B --> C["minibox now in run-xxx.scope (owned by us)"]
    C --> D["move self to run-xxx.scope/supervisor<br/>enable +cpu +memory +pids on the scope"]
    D --> E["mkdir run-xxx.scope/&lt;id&gt;, write limits"]
    E --> F["clone3(CLONE_INTO_CGROUP=&lt;id&gt;) minibox init"]
    F --> G["exit: read stats, cgroup.kill, rmdir &lt;id&gt;; systemd removes the scope"]
```

## Key decisions and why

**Why re-exec under `systemd-run`.** Moving a process between cgroups needs
write access to the *common ancestor* of the old and new cgroup. A login
shell lives in `user-1000.slice/session-N.scope`, which is root-owned, so it
can't move anything into the user-owned `user@1000.service` subtree. A
transient scope with `Delegate=yes` is created by our per-user systemd and
`chown`ed to us. Rootless Podman does the same, but over D-Bus. We call the
`systemd-run` binary instead, so we need no extra Go dependency. We
`exec` it so the terminal, signals and exit code pass straight through.

**The `supervisor` leaf.** cgroup v2's "no internal processes" rule: a
cgroup that hands controllers to its children (`cgroup.subtree_control`) may
not contain processes itself. So minibox moves itself out of the scope root
first.

**`CLONE_INTO_CGROUP`.** The child is born inside its cgroup (clone3, Linux
5.7+, Go's `SysProcAttr.UseCgroupFD`). If we moved it in after `fork`
instead, a fast child could fork processes in that gap that escape the
limits.

**Swap off.** In cgroup v2, `memory.max` covers RAM only. This VM has 4 GB
of swap, so without `memory.swap.max=0` a memory hog would just swap instead
of being stopped.

**`--pids` minimum of 8.** `pids.max` counts threads. The container's first
task is `minibox init` (Go), whose runtime starts several threads before it
execs your command: 5 measured on this VM by default, 3-4 after we start init
with `GOMAXPROCS=1`. With `--pids 3` the Go runtime crashed, so we reject
values below 8 with an explanation.

**Cleanup.** After the container exits we read its stats, write
`cgroup.kill` (a safety net; the PID namespace already killed everything),
and `rmdir` the cgroup, retrying while the kernel finishes releasing the
last task (EBUSY). systemd removes the transient scope (`--collect`).

## Tests (`tests/smoke.sh`)
- 200 MiB `dd` buffer under `--memory 50m`: exit 137, `oom_kill=1`, `memory.peak` exactly 50 MiB.
- Bounded fork tree (about 380 tasks unlimited) under `--pids 20`: `pids.peak` = 20, refused forks reported.
- No cgroups left after exit.
- CPU-bound shell loop under `--cpus 0.25`: at least 2.5x slower than unlimited
  (ideal 4x), and `nr_throttled > 0`. Measured 4.3x-7.5x over 4 runs on
  2026-10-25. Skip with `MINIBOX_SKIP_CPU=1`.

## Resolved: vCPU stalls on the VM
At first, a throttled busy loop sometimes ignored SIGKILL for 10-60+ s, and
`usage_usec` reported 27 s of CPU for a 3 s run. `scripts/repro-cpu-throttle.sh`
reproduced it **without minibox** (plain `systemd-run -p CPUQuota=25%`). The
guest kernel log showed `soft lockup - CPU#N stuck for 27-84s`, RCU stalls and
clocksource gaps of up to 60 s: the VirtualBox host (hybrid P/E-core CPU) was
not running the VM's virtual CPUs for long stretches, and a task that is never
scheduled can't act on a pending signal.

After the host-side fix, `repro-cpu-throttle.sh 10 3` killed all 10 trials
within 0.7 s and the kernel log is clean, so the CPU test is now on by
default. `scripts/check-env.sh` still warns if stalls come back, because they
would also invalidate every Phase 6 timing benchmark.
