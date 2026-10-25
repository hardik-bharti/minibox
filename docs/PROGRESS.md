# Progress

## Current phase

**Phase 0 (Setup): done.** Waiting for go-ahead to start Phase 1 (Isolation).

## Done

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

Phase 1: `minibox run <rootfs> <cmd>` with PID/mount/UTS/IPC/user namespaces,
an overlayfs root, pivot_root, a fresh /proc, a hostname, and cleanup on exit.

## Open issues
- `uidmap` (newuidmap/newgidmap) is not installed. `/etc/subuid` already has
  a range for `hardik` (100000:65536). Not needed for Phase 1, which maps only
  container root to our UID. Install it only if we later want multi-UID containers.
