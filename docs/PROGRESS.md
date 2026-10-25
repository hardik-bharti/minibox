# Progress

## Current phase

**Phase 7 (write-up): in progress.** Phase 6 is done. The user asked
(2026-10-25) for Phases 3-7 in one go, with no stop between phases.

## Done

### Phase 6: Evaluation (2026-10-25)
- Attack suite: `tests/attacks/probe` (17 attacks, static Go binary mounted
  read-only) and `tests/attacks/run.py` (none / baseline+limits /
  policy+limits). Results: none 7/17 blocked, baseline 16/17 (raw socket
  allowed via Docker's default CAP_NET_RAW), policy 17/17. See
  `results/attacks.md`.
- **Finding:** a name-only allowlist let `clone(CLONE_NEWUSER)` through, so
  the unshare attack succeeded under policy. Fixed with Docker's rule
  (`clone` without namespace flags, `clone3` gets ENOSYS) unless the policy
  has CAP_SYS_ADMIN.
- Benchmarks: `bench/run.py` with `tools/loadgen` (startup, cpu-python,
  syscall-dd, python-http, busybox-http), 5 reps (30 for startup),
  interleaved, with warm-up, mean/sd/median. `--report-only` regenerates
  tables from the CSV.
- Syscall counts: `tools/policystats` (Docker baseline vs generated
  policies). `scripts/update-docs-results.py` copies the generated tables
  into docs between markers.
- Harness bugs fixed along the way: unread stderr pipe blocked http.server
  (now goes to a file), and HTTP concurrency of 8 hit tiny listen backlogs
  (1 s SYN retries, seen even on the bare host), so we use 1 client.
- `make attacks`, `make bench`, `make bench-image`.

### Phase 5: Profiling and policy enforcement (2026-10-25)
- `minibox profile [run flags] [-o policy.json] [--merge] <rootfs> <cmd>`
  and `minibox run --policy FILE`. Package `internal/profile`.
- ptrace tracer (eBPF needs root here: unprivileged_bpf_disabled=2).
  Uses PTRACE_GET_SYSCALL_INFO and follows forks/clones. Recording starts
  at the first PTRACE_EVENT_EXEC (the user's command), so minibox's own
  setup syscalls are excluded.
- Paths read from /proc/pid/mem, resolved through /proc/pid/cwd and fd/N,
  classified read / write / parent-dir write. Writable paths minimised.
- Capabilities inferred from syscalls + args (bind port < 1024, raw sockets,
  chown, ...) with recorded reasons. A DAC_OVERRIDE false positive for
  world-writable /dev/null was fixed.
- Enforcement: allowlist seccomp (EPERM default, plus execve/exit/
  exit_group/rt_sigreturn/restart_syscall), listed caps only, `/` remounted
  read-only with rw binds for writable paths, plus the baseline masks and NNP.
- Bug found and fixed: binding `/` onto itself before the read-only
  remount left a hidden rw copy of the root. Now `/` is only remounted.
- Also added `-v HOST:CONTAINER[:ro]` volumes, and
  `scripts/build-bench-image.sh` (images/bench = Alpine + python3 +
  busybox-extras, installed with apk --root through a volume).
- Verified manually: a Python http.server profiled under curl load (46
  syscalls) serves correctly under its policy.
- Tests: profile unit tests (writable path minimisation, merge, table
  sanity), CLI tests, 14 smoke checks.

### Phase 4: Baseline security (2026-10-25)
- `--security baseline|none` (default baseline). Package `internal/security`.
- Docker's 14 default caps (CapEff/CapBnd = 0xa80425fb), bounding set
  dropped, ambient set cleared.
- Docker's default seccomp profile embedded unmodified
  (`internal/security/profiles/docker-default.json`, moby/profiles
  seccomp/v0.2.4, sha256 pinned in `scripts/get-docker-profile.sh`) and
  compiled to BPF by our own pure-Go compiler (no cgo, no libseccomp).
  We also kill the i386 ABI and deny the x32 ABI.
- Docker's masked and read-only paths. no_new_privs.
- Init locks its OS thread because caps, NNP and seccomp are per-thread.
  The filter is installed without TSYNC, right before execve.
- Syscall table generated from the kernel UAPI header
  (`scripts/gen-syscalls.sh`).
- Tests: BPF interpreter-based unit tests, caps/policy tests, CLI tests, 19
  smoke checks (including `--security none` controls).

### Phase 3: Networking (2026-10-25)
- `--net none|bridge` (default `none`) and `-p HOST:CONTAINER[/proto]`.
  Package `internal/network`.
- Every container gets `CLONE_NEWNET`. `lo` is brought up via ioctl.
- bridge = rootless slirp4netns 1.3.3: tap0 10.0.3.100/24, gw 10.0.3.2,
  DNS 10.0.3.3 (CIDR moved off 10.0.2.0/24 because VirtualBox NAT uses it).
  Started with `--enable-sandbox --enable-seccomp --disable-host-loopback
  --mtu=65520`. Port forwards go through its API socket (`add_hostfwd`).
- No race: init blocks on its config pipe until slirp reports ready.
  `--exit-fd` makes slirp exit even if minibox is SIGKILLed (tested).
- `/sys` now mounted read-only (needs our own netns). Closes a Phase 1 issue.
- Bridge mode writes `/etc/resolv.conf` through the overlay.
- Chose slirp4netns over veth+bridge+iptables because the latter needs root
  in the host netns (sudo needs a password here). Tradeoff table in
  `docs/phase3-networking.md`.
- Tests: `internal/network/config_test.go`, CLI flag tests, 16 new smoke
  checks (none/bridge, outbound NAT to VM IP, host loopback blocked, -p,
  internet+DNS when online, busy port error, no slirp/state left behind).
  `check-env.sh` reports slirp4netns and /dev/net/tun (optional).

### Phase 2: Resource limits (2026-10-25)
- Flags `--memory`, `--cpus`, `--pids`, `--stats`; package `internal/cgroups`.
- Automatic re-exec under `systemd-run --user --scope -p Delegate=yes` when
  not in a delegated cgroup; `supervisor` leaf; `CLONE_INTO_CGROUP`;
  `memory.swap.max=0`; cleanup with `cgroup.kill` + rmdir.
- init started with `GOMAXPROCS=1`, and `--pids` minimum 8 (pids.max counts Go threads).
- OOM kills and refused forks are reported after exit.
- Tests: unit tests (`internal/cgroups/limits_test.go`); smoke tests for the
  memory OOM kill, the bounded fork tree capped at 20, validation and cgroup
  cleanup, and the CPU throttle test (4.3x-7.5x slower at `--cpus 0.25`,
  `nr_throttled > 0`; on by default, `MINIBOX_SKIP_CPU=1` skips it).
- VM vCPU stalls fixed on the host by the user. `repro-cpu-throttle.sh 10 3`
  now kills all trials within 0.7 s. check-env.sh ignores the single ~1 s
  boot-time clocksource readout that VirtualBox always logs.
- `scripts/repro-cpu-throttle.sh` (minimal repro without minibox) and a
  vCPU-stall check in `check-env.sh`.
- Write-up: `docs/phase2-cgroups.md`.

### Phase 1: Isolation (2026-10-25)
- `minibox run [--hostname h] <rootfs> <cmd> [args...]`.
- New user/PID/mount/UTS/IPC namespaces via re-exec of `/proc/self/exe init`;
  container 0 maps to our UID/GID (single-ID map, setgroups denied).
- overlayfs root (image read-only, per-container upper/work), tmpfs `/dev` with
  bind-mounted host null/zero/full/random/urandom/tty, fresh `/proc`,
  pivot_root plus a lazy unmount of the old root, hostname.
- Clean environment for the command (PATH, HOME, HOSTNAME, TERM).
- Exit code propagation (128+N for signals, 127 for setup failure); signal
  forwarding with escalation to SIGKILL on the second signal; Pdeathsig.
- Cleanup: mounts die with the mount namespace; state dir removed (handles
  overlay's mode-000 `work/work`).
- Tests: unit tests in `internal/container/config_test.go`; 28 end-to-end
  checks in `tests/smoke.sh` (namespace inode comparison, uid_map, PID 1, host
  processes hidden, hostname, host fs unreachable, overlay copy-on-write,
  exit codes, stdin, cleanup, no leaked mounts).
- Design write-up: `docs/phase1-isolation.md`.
- Gotcha found: `/proc` must be mounted **before** pivot_root (kernel
  `mnt_already_visible` check). Mounting it afterwards gives EPERM.

### Phase 0: Setup (2026-10-25)
- `scripts/check-env.sh`: checks for an unprivileged user, kernel >= 5.11, Go,
  cgroup v2 plus delegated controllers, user namespaces (sysctls and a real
  `unshare` test), overlayfs (a real mount inside a userns), optional
  subuid/newuidmap, and the download tools.
- `scripts/get-alpine.sh`: finds the latest Alpine minirootfs from the release
  index, verifies its SHA-256, and unpacks it into `images/alpine` (git-ignored).
  Last run fetched Alpine 3.24.3.
- Go module `github.com/hardik-bharti/minibox`, CLI skeleton with `run`/`profile` stubs, and empty
  `internal/` packages, one per phase.
- Makefile targets: build, test, smoke, vet, fmt, check-env, image, clean.
- Tests: CLI dispatch unit test (`cmd/minibox/main_test.go`) and
  `tests/smoke.sh`.

### Environment findings
- Kernel 7.0.0-38-generic, cgroup2fs, and the controllers delegated to the
  user are `cpu memory pids`. That's enough for Phase 2.
- overlayfs is a loadable module (`CONFIG_OVERLAY_FS=m`). It isn't listed in
  `/proc/filesystems` until first use, but rootless mounts work.
- `kernel.apparmor_restrict_unprivileged_userns=0` and the user namespace test
  passes.

## Next

1. Phase 7: README (architecture, results, limitations, related work),
   how-it-works.md, viva-prep.md, team split.

## Open issues
- If minibox itself is SIGKILLed, its container dir under
  `~/.local/share/minibox/containers/` is left behind (the container itself is
  killed). Possible fix later: a `minibox prune` command.
- slirp4netns runs outside the container cgroup (its usage is not charged
  to the container). Containers cannot reach each other (no shared bridge).
- PID 1 inside is the user's command, so it must reap zombies itself (like
  `docker run` without `--init`).
- `uidmap` (newuidmap/newgidmap) is not installed. `/etc/subuid` already has
  a range for `hardik` (100000:65536). Not needed for Phase 1, which maps only
  container root to our UID. Install it only if we later want multi-UID containers.
