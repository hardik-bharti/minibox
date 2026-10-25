# Phase 5: Profiling mode and policy enforcement

Code: `internal/profile/` (`tracer.go` = ptrace loop, `recorder.go` =
classifying syscalls/paths/capabilities, `profile.go` = building and merging
policies), `internal/security/policy.go` (file format) and `apply.go`
(enforcement). CLI: `minibox profile` in `cmd/minibox/run.go`.

## Usage

```sh
# 1. Profile: run the app (and exercise it), then let it exit or press Ctrl-C.
./bin/minibox profile -o py.json --net bridge -p 8080:8000 images/bench python3 -m http.server 8000
#    ...in another terminal: curl http://127.0.0.1:8080/ a few times, then Ctrl-C the profile.
# minibox profile: 46 syscalls, 0 capabilities [], 0 writable paths [] -> py.json

# 2. Enforce:
./bin/minibox run --policy py.json --net bridge -p 8080:8000 images/bench python3 -m http.server 8000

# Optional: profile under several workloads and merge (union) the results.
./bin/minibox profile -o app.json --merge images/alpine sh -c '...'
```

`profile` takes all `run` flags except `--security`/`--policy`. The container
runs with **no** restrictions while being profiled (no seccomp, all
capabilities), so the trace shows everything the program tries, not just what
an earlier policy let it do.

## The policy file

```json
{
  "minibox_policy": 1,
  "generated": "2026-10-25T12:00:00Z",
  "command": ["sh", "-c", "..."],
  "syscalls": ["arch_prctl", "brk", "close", "..."],
  "capabilities": ["CAP_NET_BIND_SERVICE"],
  "writable_paths": ["/tmp", "/var/cache"],
  "observed": {
    "syscall_counts": {"read": 120, "...": 1},
    "capability_reasons": {"CAP_NET_BIND_SERVICE": "bind to port 80"},
    "read_paths": ["/etc/os-release", "..."],
    "written_paths": ["/tmp", "/var/cache", "/var/cache/app"]
  }
}
```

The top three lists are enforced. `observed` is there for people to review
and for the Phase 6 scripts.

## What `run --policy` enforces

| Policy field | Enforcement |
|--------------|-------------|
| `syscalls` | seccomp **allowlist**: everything else returns `EPERM`. Five syscalls are always allowed: `execve` (the filter is installed before it), `exit`, `exit_group`, `rt_sigreturn`, `restart_syscall` (kernel plumbing; none adds any ability). |
| `capabilities` | Exactly these. Bounding/effective/permitted/inheritable are set as in Phase 4. Often the list is empty. |
| `writable_paths` | `/` remounted **read-only**. Each listed path first gets its own read-write bind mount. Writes still land in the overlay's upper layer. |
| (always) | Phase 4's masked/read-only `/proc` and `/sys` paths and no_new_privs. |

## Why ptrace, not eBPF

The project brief asked for eBPF if feasible. On this VM it isn't, without
root:

- `kernel.unprivileged_bpf_disabled = 2`, Ubuntu's default. Loading any BPF
  program needs `CAP_BPF` and, for tracing, `CAP_PERFMON` in the *initial*
  user namespace, i.e. real root. Being root inside our user namespace
  doesn't count.
- `bpftrace` is installed but needs `sudo`, which conflicts with minibox's
  rootless design (and needs a password here).

ptrace works unprivileged because we trace our own descendants
(`kernel.yama.ptrace_scope = 1` allows that). Tradeoffs:

| | ptrace (chosen) | eBPF |
|---|---|---|
| Privilege | none | root (`CAP_BPF` + `CAP_PERFMON`) |
| Overhead | two context switches to the tracer per syscall: slow, but only while profiling | small, in kernel |
| Sees capability checks | **no**, so we infer them (below) | yes (kprobe on `cap_capable`) |
| Sees syscall args/paths | yes, reads tracee memory | yes |

An alternative we didn't pick is seccomp `SECCOMP_RET_USER_NOTIF` (a
supervisor gets each syscall). It's also rootless, but it's harder to
follow every child process with it, and ptrace is the classic concept.

## How the tracer works (`tracer.go`)

1. `container.Run` starts init with `SysProcAttr.Ptrace = true`. The child
   calls `PTRACE_TRACEME` and stops at its first exec (minibox re-executing
   itself as `init`).
2. We set options: `TRACESYSGOOD` (syscall stops are marked),
   `TRACECLONE/FORK/VFORK` (follow every thread and child), `TRACEEXEC`, and
   `EXITKILL` (if minibox dies, the traced container dies too).
3. Loop: `wait4(-1, __WALL)` → `PTRACE_GET_SYSCALL_INFO` tells us whether
   the stop is a syscall **entry** (number + 6 args) or **exit** (return
   value). The kernel says which, so there's no fragile entry/exit toggle.
4. **Recording starts at the first `PTRACE_EVENT_EXEC`**: init exec'ing the
   user's command. Everything before that is minibox's own setup (mount,
   pivot_root, ...), which must not end up in the app's policy. This
   matches enforcement exactly: the filter is installed just before that
   execve.
5. Path arguments are read from `/proc/<pid>/mem` at syscall entry. Relative
   paths are resolved with `/proc/<pid>/cwd` or `/proc/<pid>/fd/<dirfd>`.
   Seen from the host, these already show container paths, because the
   container's root is outside our mount namespace. We can look at files
   through the container's eyes via `/proc/<pid>/root/<path>`.
6. All ptrace calls come from one OS thread: Linux ties tracer status to a
   thread, and `container.Run` already locks it.

## Classifying file access (`recorder.go`)

| Syscall | Recorded as |
|---------|-------------|
| `open*` without write flags, `stat*`, `access`, `readlink`, `execve`, `chdir` | read |
| `open*` with `O_WRONLY/O_RDWR/O_TRUNC/O_APPEND`, `chmod`, `chown`, `truncate`, `utimensat`, `setxattr` | write to that file |
| `open*` with `O_CREAT` of a file that didn't exist, `mkdir`, `unlink`, `rmdir`, `rename`, `link`, `symlink`, `mknod` | write to the **parent directory** (its entries change) |

Only successful writes count. `writable_paths` is then minimised: paths
inside a writable directory are dropped, and `/dev`, `/proc`, `/sys` (separate
mounts, handled by masking) and `/` itself (that would defeat the read-only
root) are excluded. For example, `{/tmp, /tmp/a.txt, /var/log/app.log}`
becomes `{/tmp, /var/log/app.log}`.

## Inferring capabilities

ptrace sees syscalls, not the kernel's internal `capable()` checks. So we
infer from successful syscalls and their arguments, following
capabilities(7), and record the reason in `observed.capability_reasons`:

| Observation | Capability |
|-------------|------------|
| `bind()` to an AF_INET/AF_INET6 port < 1024 (sockaddr read from memory) | `CAP_NET_BIND_SERVICE` |
| `socket(AF_INET*, SOCK_RAW)` or `AF_PACKET` | `CAP_NET_RAW` |
| `chown` family | `CAP_CHOWN` |
| `set*uid` / `set*gid` / `setgroups` | `CAP_SETUID` / `CAP_SETGID` |
| `chroot` | `CAP_SYS_CHROOT` |
| `mount`, `unshare`, `setns`, `sethostname`, `clone` with namespace flags | `CAP_SYS_ADMIN` |
| `settimeofday`, `clock_settime` | `CAP_SYS_TIME` |
| `mknod` of a char/block device | `CAP_MKNOD` |
| `setxattr("security.capability")` | `CAP_SETFCAP` |
| write to a file not owned by container root and not world-writable | `CAP_DAC_OVERRIDE` |
| chmod/chown/utime on a file not owned by container root | `CAP_FOWNER` |

The smoke tests check this end to end. `nc -l -p 80` gives
`CAP_NET_BIND_SERVICE`. Removing it from the policy makes the bind fail with
"Permission denied", which shows that the policy's capability list really is
what's enforced.

## Limitations (important for the evaluation)

- **Coverage.** The policy contains only what the profiled run did. An
  untested code path, such as an error handler or a rarely used feature,
  may need a syscall that isn't there, and it gets `EPERM`. Mitigations:
  exercise the app well while profiling, and use `--merge` to combine runs.
  This is the same tradeoff as SlimToolkit and oci-seccomp-bpf-hook.
- Capability inference is heuristic, not observed. The reasons are
  recorded so a human can review them.
- No argument filtering in policies (e.g. `socket` is allowed for every
  family once seen). Docker's profile has a few argument rules, and ours
  are name-only.
- ptrace makes the profiled run much slower. It's only used during
  profiling, never with `run --policy`.
- Volumes (`-v`) are separate mounts and stay writable unless `:ro`.
