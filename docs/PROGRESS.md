# Progress

## Current phase

**Phase 3 (networking): next.** Phase 2 is done. The user asked for Phases
3-7 to be completed in one go (2026-10-25).

## Done

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

1. Phase 3: networking (`--net`).

## Open issues
- If minibox itself is SIGKILLed, its container dir under
  `~/.local/share/minibox/containers/` is left behind (the container itself is
  killed). Possible fix later: a `minibox prune` command.
- No `/sys` in the container yet (sysfs needs our own network namespace, Phase 3).
- PID 1 inside is the user's command, so it must reap zombies itself (like
  `docker run` without `--init`).
- `uidmap` (newuidmap/newgidmap) is not installed. `/etc/subuid` already has
  a range for `hardik` (100000:65536). Not needed for Phase 1, which maps only
  container root to our UID. Install it only if we later want multi-UID containers.
