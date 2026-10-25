# Phase 6: Evaluation

Everything here is produced by scripts in the repo. Re-run them with:

```sh
make bench-image        # once: images/bench = Alpine + python3 + busybox httpd
make attacks            # tests/attacks/run.py -> results/attacks.{csv,md}
make bench              # bench/run.py -> results/bench.{csv,md}, results/syscalls.{csv,md}
```

Both targets then run `scripts/update-docs-results.py`, which copies the
generated tables into this file and the README. The tables between the
`results:` markers are never edited by hand. Raw per-run data is in the CSVs.

## The three configurations

| Config | Flags | What it means |
|--------|-------|---------------|
| none | `--security none` | Namespaces only: container root has every capability in its user namespace, no seccomp, nothing masked. No resource limits. |
| baseline | default, plus `--pids 64 --memory 256m` in the attack suite | Phase 4: Docker's capabilities and seccomp profile, masked paths, no_new_privs |
| policy | `--policy <generated>`, plus the same limits in the attack suite | Phase 5: profiled syscall allowlist, inferred capabilities, read-only root except observed writes, plus the masks and no_new_privs |

The attack suite adds resource limits to the two hardened configurations,
because fork bombs and memory exhaustion are stopped by cgroups, not by
seccomp. The benchmarks use no limits in any configuration, so they
measure only the cost of the security mechanisms.

## Attack suite

`tests/attacks/probe` is one static Go binary with a subcommand per
attack, mounted read-only into the container. Each attack prints BLOCKED or
ALLOWED with the error it got. All attacks are self-contained policy and
misconfiguration tests: nothing exploits a kernel bug, and anything that
could have an effect is bounded or undone (the fork bomb stops at 500
processes, memory at 1 GiB, sysrq is opened but never written, and the
clock is "set" to its current value).

The **policy** configuration is a policy for a normal small service:
`probe benign` (read a config file, write and delete a temp file, spawn a
helper, allocate 16 MiB, open a TCP socket), profiled three times and
merged. It's generated fresh by `run.py` and saved in
`results/policies/attack-probe.json`. Every attack then runs under that
same policy, i.e. "what if this service were compromised and the attacker
tried X".

<!-- results:attacks-matrix -->
| # | Attack | none | baseline | policy |
|---|---|---|---|---|
| 1 | mount a filesystem (tmpfs on /mnt) (`mount`) | ALLOWED | BLOCKED | BLOCKED |
| 2 | create a user namespace to regain all capabilities (`unshare`) | ALLOWED | BLOCKED | BLOCKED |
| 3 | load a kernel module (init_module) (`kernel-module`) | BLOCKED | BLOCKED | BLOCKED |
| 4 | ptrace-attach to a sibling process (`ptrace`) | ALLOWED | BLOCKED | BLOCKED |
| 5 | open /proc/sysrq-trigger for writing (`sysrq`) | BLOCKED | BLOCKED | BLOCKED |
| 6 | write /proc/sys/net/ipv4/ip_forward (`proc-sys`) | ALLOWED | BLOCKED | BLOCKED |
| 7 | read host kernel info (/proc/interrupts) (`kernel-info`) | ALLOWED | BLOCKED | BLOCKED |
| 8 | hold 500 processes (bounded fork bomb) (`fork-bomb`) | ALLOWED | BLOCKED | BLOCKED |
| 9 | allocate and touch 1 GiB (`memory`) | ALLOWED | BLOCKED | BLOCKED |
| 10 | open a raw socket (SOCK_RAW) (`raw-socket`) | ALLOWED | ALLOWED | BLOCKED |
| 11 | change the hostname (sethostname) (`hostname`) | ALLOWED | BLOCKED | BLOCKED |
| 12 | set the system clock (clock_settime) (`clock`) | BLOCKED | BLOCKED | BLOCKED |
| 13 | add a key to the kernel keyring (`keyring`) | ALLOWED | BLOCKED | BLOCKED |
| 14 | use bpf() (BPF_MAP_CREATE) (`bpf`) | BLOCKED | BLOCKED | BLOCKED |
| 15 | create a block device node for the host disk (`mknod`) | BLOCKED | BLOCKED | BLOCKED |
| 16 | classic chroot + '..' escape to the host fs (`chroot-escape`) | BLOCKED | BLOCKED | BLOCKED |
| 17 | read another container's files (`other-container`) | BLOCKED | BLOCKED | BLOCKED |
<!-- /results:attacks-matrix -->

<!-- results:attacks-summary -->
| Config | Blocked | Allowed | Error |
|---|---|---|---|
| none | 7/17 | 10 | 0 |
| baseline | 16/17 | 1 | 0 |
| policy | 17/17 | 0 | 0 |
<!-- /results:attacks-summary -->

The probe's exact error for every cell is in
[results/attacks.md](../results/attacks.md).

### Reading the results

- **Stopped by the user namespace alone** (blocked even in `none`): kernel
  module loading, setting the clock, `bpf()`, creating a device node, opening
  `/proc/sysrq-trigger`, the chroot escape, and reading another container's
  files. These need privileges in the *initial* user namespace or touch
  objects our namespace doesn't own, so being root in a user namespace
  isn't enough. This is why rootless containers are a strong starting
  point. The chroot escape fails because `pivot_root` plus detaching the old
  root leaves nothing above `/`. The other container is invisible because of
  the PID and mount namespaces.
- **Allowed with no hardening**: `mount`, `unshare` (a nested user
  namespace with all capabilities), ptrace of a sibling, the keyring,
  `sethostname`, raw sockets, writing `/proc/sys`, reading
  `/proc/interrupts`, the fork bomb and the 1 GiB allocation. Root in a user
  namespace is powerful within its namespaces.
- **Baseline** blocks all of those except **raw sockets**. Docker's default
  capability set includes `CAP_NET_RAW`, used for ping, and our baseline
  copies it. Fork bomb and memory are stopped by the cgroup limits
  (`pids.max`, OOM kill). ptrace is stopped by Yama, since without
  `CAP_SYS_PTRACE` only descendants may be traced, even though Docker's
  seccomp profile allows `ptrace`.
- **Policy** also blocks raw sockets: the benign service never used one,
  so no `CAP_NET_RAW`. Most other attacks are blocked earlier than in the
  baseline, because their syscall (`mount`, `ptrace`, `add_key`,
  `sethostname`, `chroot`, ...) isn't in the allowlist at all.

### A weakness the suite found (and the fix)

The first version of policy mode allowed syscalls by **name only**. The
benign service uses `clone` (to spawn its helper), so `clone` was allowed
with *any* flags. Creating a user namespace needs no capability, so
`clone(CLONE_NEWUSER)` worked and the `unshare` attack succeeded under the
generated policy, even though the baseline blocked it. Docker's profile
avoids this with an argument rule. We added the same to policy mode
(`internal/security/apply.go`, `policyFilter`): `clone` is allowed only
without namespace flags, and `clone3` returns `ENOSYS` (its flags are in
memory, where seccomp can't see them), so libc and Go fall back to `clone`.
Policies whose app really creates namespaces carry the inferred
`CAP_SYS_ADMIN` and keep plain `clone`. Unit test:
`TestPolicyRestrictsClone`. The table above is from after the fix.

## Benchmarks

`bench/run.py` measures five workloads under all three configurations.
For each workload the policy is generated by profiling that same workload
(the servers are profiled while `tools/loadgen` drives them), two runs
merged.

| Workload | What is measured |
|----------|------------------|
| `startup` | wall time of `minibox run images/alpine true`: namespaces, overlay, mounts, security setup, exec, cleanup |
| `cpu-python` | wall time of a CPU-bound Python loop (6M iterations), including startup |
| `syscall-dd` | wall time of `dd bs=1 count=500000`: about 1M `read`/`write` syscalls, the worst case for per-syscall seccomp cost |
| `python-http` | `python3 -m http.server`: requests/s and latency from `tools/loadgen`, through `-p`/slirp4netns |
| `busybox-http` | `busybox httpd`, same method |

Method: configurations are interleaved (none, baseline, policy, none, ...)
so slow drift in the VM affects all of them alike. There's one unmeasured
warm-up run per cell. HTTP uses one client and a new connection per
request. With more concurrent clients, both servers' tiny listen backlogs
(Python's `socketserver` uses 5) drop connection attempts that TCP retries
after about 1 s. We saw this with the server running directly on the host
too, so it has nothing to do with containers, but it dominated the means.

<!-- results:bench -->
Environment: minibox-dev, kernel 7.0.0-38-generic, 4 vCPUs, 2026-10-25 16:36 UTC. Repetitions per cell: 5 (HTTP: 10 s of load each after 1 s warm-up, 1 client, new connection per request, through slirp4netns in every config).

Startup has 30 repetitions per cell (it is cheap).

Cells: mean ± sample standard deviation, then the median. *Overhead* compares each configuration with `none`, by mean and by median (positive = worse: slower, or fewer requests/s). The median is less sensitive to a single slow run.

| Workload | Metric | none | baseline | policy | baseline overhead (mean / median) | policy overhead (mean / median) |
|---|---|---|---|---|---|---|
| startup | wall_time (ms) | 8.00 ± 1.32 (med 7.71) | 9.31 ± 1.51 (med 9.07) | 8.98 ± 1.47 (med 8.75) | +16.3% / +17.6% | +12.2% / +13.5% |
| cpu-python | wall_time (ms) | 609.99 ± 35.41 (med 609.14) | 657.39 ± 38.42 (med 646.41) | 628.50 ± 27.87 (med 638.10) | +7.8% / +6.1% | +3.0% / +4.8% |
| syscall-dd | wall_time (ms) | 204.20 ± 11.72 (med 205.50) | 231.85 ± 12.49 (med 235.37) | 251.29 ± 46.06 (med 227.82) | +13.5% / +14.5% | +23.1% / +10.9% |
| python-http | rps (req/s) | 1622.51 ± 70.13 (med 1657.41) | 1646.76 ± 23.26 (med 1647.48) | 1631.83 ± 56.75 (med 1644.07) | -1.5% / +0.6% | -0.6% / +0.8% |
| python-http | lat_mean_ms (ms) | 0.62 ± 0.03 (med 0.60) | 0.61 ± 0.01 (med 0.61) | 0.61 ± 0.02 (med 0.61) | -1.6% / +0.5% | -0.7% / +0.7% |
| python-http | lat_p50_ms (ms) | 0.56 ± 0.02 (med 0.55) | 0.55 ± 0.01 (med 0.55) | 0.56 ± 0.02 (med 0.55) | -1.7% / +0.2% | -0.1% / +0.7% |
| python-http | lat_p99_ms (ms) | 1.52 ± 0.08 (med 1.50) | 1.48 ± 0.07 (med 1.49) | 1.48 ± 0.09 (med 1.46) | -2.2% / -0.7% | -2.7% / -2.7% |
| busybox-http | rps (req/s) | 1601.69 ± 344.64 (med 1407.75) | 1285.98 ± 528.19 (med 1244.46) | 1358.06 ± 71.94 (med 1361.69) | +19.7% / +11.6% | +15.2% / +3.3% |
| busybox-http | lat_mean_ms (ms) | 0.65 ± 0.13 (med 0.71) | 0.74 ± 0.15 (med 0.80) | 0.74 ± 0.04 (med 0.73) | +14.6% / +12.4% | +14.2% / +3.4% |
| busybox-http | lat_p50_ms (ms) | 0.25 ± 0.01 (med 0.25) | 0.25 ± 0.00 (med 0.25) | 0.25 ± 0.00 (med 0.25) | -0.4% / -1.2% | +0.6% / -0.4% |
| busybox-http | lat_p99_ms (ms) | 0.81 ± 0.05 (med 0.81) | 0.80 ± 0.04 (med 0.80) | 0.83 ± 0.02 (med 0.83) | -1.8% / -0.7% | +2.7% / +2.9% |
<!-- /results:bench -->

### Reading the results

- **Web servers: no measurable cost.** For `python-http`, every
  configuration's mean and median are within each other's run-to-run
  spread. A request costs well under a millisecond, and the few hundred
  syscalls it makes are noise next to the work done in slirp4netns and
  Python. `busybox-http`'s throughput varies a lot between runs of the
  *same* configuration (see the standard deviations and
  `results/bench.csv`), much more than between configurations, so its
  differences aren't meaningful. Each busybox run had exactly one request
  slower than 500 ms in every configuration (CSV column `slow_over_500ms`),
  a TCP retransmit unrelated to hardening.
- **Startup** is a few milliseconds in every configuration. The hardened
  ones add about a millisecond: parsing and compiling the seccomp filter,
  the extra masking mounts, and in policy mode the read-only remount.
- **Worst case, `syscall-dd`**: about a million trivial syscalls, so any
  per-syscall cost shows. Both hardened configurations are measurably
  slower than `none`. By median, policy isn't slower than baseline: one
  slow first policy run inflates its mean (per-run values are in the CSV).
  A likely reason the much shorter policy filter is no faster: since
  Linux 5.11 the kernel caches syscalls whose filter result is always
  "allow" regardless of arguments (the seccomp action cache), so for
  `read`/`write` neither filter's BPF actually runs. What remains is the
  fixed cost of having seccomp enabled on the syscall path. This is an
  explanation from kernel documentation, not something these benchmarks
  isolate.
- **`cpu-python`** makes few syscalls, so seccomp should cost almost
  nothing. The small differences are within the spread of a 4-vCPU VM.

### Attack-surface reduction: syscall counts

Docker's profile is a *denylist in spirit*: it allows everything except
known-dangerous syscalls, so any program runs. A generated policy allows
only what the workload used. Counts are syscalls the compiled filter
allows in any form, for both sides, including the policy's few always-allowed
syscalls (`tools/policystats`):

<!-- results:syscalls -->
| Profile | Allowed syscalls | % of Docker's | Allowed but not in Docker's | Capabilities | Writable paths |
|---|---|---|---|---|---|
| docker-default (baseline) | 309 | 100.0% | - | 14 | all (rw root) |
| attack-probe | 42 | 13.6% | - | 0 | /tmp |
| busybox-http | 28 | 9.1% | - | 0 | none (read-only root) |
| cpu-python | 31 | 10.0% | - | 0 | none (read-only root) |
| python-http | 49 | 15.9% | - | 0 | none (read-only root) |
| startup | 11 | 3.6% | - | 0 | none (read-only root) |
| syscall-dd | 19 | 6.1% | - | 0 | none (read-only root) |
<!-- /results:syscalls -->

In the recorded run, the "Allowed but not in Docker's" column is empty:
every generated policy is a subset of Docker's allowlist, so none is
looser than the baseline on syscalls. (This isn't guaranteed in general.
An app that really needs, say, `mount` would get it in its policy, along
with the inferred `CAP_SYS_ADMIN`.) The table also shows that these
policies keep no capabilities and, except the attack probe's `/tmp`, no
writable paths: the root filesystem is entirely read-only.

## Threats to validity

- One VM, 4 vCPUs, with the load generator on the same machine as the
  server. Absolute numbers depend on the host. Compare configurations
  with each other, not with other papers.
- Five repetitions per cell (30 for startup). The standard deviations show
  how much to trust each difference.
- Policies cover only what profiling exercised. The benchmarks run the
  same workload that was profiled, which is the best case for policy
  mode. A real deployment needs more thorough profiling (see
  `docs/phase5-profiling.md`, Limitations).
- All HTTP traffic goes through slirp4netns in every configuration, which
  dominates the network cost and may hide small differences.
