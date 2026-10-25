# Progress

## Current phase

**Phase 1 (Isolation): done.** Waiting for go-ahead to start Phase 2 (cgroups v2).

## Done

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

Phase 2: `--memory`, `--cpus`, `--pids` via a per-container cgroup v2 under
our systemd-delegated subtree; remove it on exit; tests for an OOM kill, a
capped fork bomb and CPU throttling.

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
