# Phase 8: Demo UI and explainer

Two ways to *show* what minibox does, for demos and the viva:

| | `minibox ui` (live dashboard) | Explainer (`docs/explainer.html`) |
|---|---|---|
| What it is | A web page served from the VM that runs real containers | A self-contained page, also published on claude.ai |
| Data | Live: cgroup files, the profiler's event log, real command output | Generated: `tools/bpfdump` and `results/*.csv`, via `make explainer` |
| Needs | The VM, `bin/minibox`, `images/alpine` (the probe and bench image are optional) | Nothing: any browser |
| Best for | Proving it works, in front of the examiner | Explaining how it works, before or after |

## Running the dashboard

```sh
make ui                      # builds minibox and the probe, then serves http://127.0.0.1:7070
```

The server listens on loopback only. To open it from your host machine,
tunnel through SSH. This needs the VirtualBox port forward from the README
(host 2222 → guest 22):

```sh
ssh -p 2222 -L 7070:127.0.0.1:7070 hardik@127.0.0.1    # on the host, then open http://127.0.0.1:7070
```

Ctrl-C stops the server. A running demo is stopped first, the same way
Ctrl-C stops `minibox run`, so its container is cleaned up.

## The five panels

| Panel | What you do | What you see | Where the numbers come from |
|---|---|---|---|
| Phase 1, Isolation | Compare host and container; change a file in the image | Host and container side by side: namespace inodes, UID, uid_map, PID, process count, hostname, root filesystem, mounts, interfaces, home directory | `/proc/self/*` of the server and of the container (`isolationScript`) |
| Phase 2, Resource limits | Memory hog, fork loop or CPU burner, with a chosen limit | A live line chart against the limit line, the OOM kill or first refused fork marked, plus the final `--stats` | The container's cgroup files, read every 100 ms (`cgwatch.go`) |
| Phase 5, Profile and enforce | Profile one of several programs, then run any of them under any generated policy | Syscalls appearing as they're first made, files read and written, inferred capabilities; Docker's 309 syscalls with the kept ones lit; whether the run succeeded and the "Operation not permitted" lines | `minibox profile --events` (JSON lines) and the policy file |
| Phase 6, Attack suite | Run one attack or all 17 | The 3-configuration matrix filling in, with the probe's own report for each cell | The probe's `BLOCKED`/`ALLOWED` line, read like `tests/attacks/run.py` does |
| Phases 4–5, Inside the filter | Pick a filter and a syscall | The real BPF program, the path that syscall takes, step by step, and the verdict | `security.Disassemble` and `security.Evaluate` on the compiled filter |

Every panel shows a dark **command strip** under its controls. It holds
the exact `minibox` command being run and its exit code, and the full
output is in the log below. Nothing on the page is simulated.

## Design decisions

**The server runs the CLI rather than calling the packages.** Each demo
starts `bin/minibox run ...` as a child process. This has three benefits.
The page can honestly say "this is the command" and show it. A crash in a
demo can't take the server down. And signal handling, cgroup re-exec and
cleanup are exercised exactly as from a terminal. The cost is a few
milliseconds per demo.

**Live meters come from the kernel, not from minibox.** `minibox` moves
itself into `<scope>/supervisor` and creates `<scope>/<container-id>` (see
`cgroups.Create`). From the child's PID the server reads
`/proc/<pid>/cgroup`; once that ends in `/supervisor`, the container's
cgroup is the other directory next to it. No changes to `minibox run` were
needed.

**Live profiling needed one small hook.** `minibox profile --events FILE`
writes a JSON line the *first* time each syscall, path or capability is
seen, plus a running total at most every 200 ms. A line per syscall would
slow the traced program a lot (a Python start-up makes thousands). The
file is opened with `O_CLOEXEC`, so the container can't inherit it and
write fake events.

**Safety, because a browser is involved.**
- It listens on `127.0.0.1` by default. `--addr` can change that, with a warning.
- There's a fixed catalogue of actions (`actions.go`). Every parameter must be one of
  the offered choices, so there is no input that becomes a command line.
- `POST` requests need an `X-Minibox-UI: 1` header. A web page from another
  site can't add a custom header to a cross-origin request without a CORS
  preflight, which the server never approves.
- The `Host` header must be `localhost` or an IP literal. This blocks DNS
  rebinding, where a malicious domain resolves to 127.0.0.1 to look same-origin.
- One demo at a time, with a timeout on each command and a Stop button.
- A Content-Security-Policy header limits the page to its own scripts.

**Standard library only.** It uses `net/http`, `embed` and server-sent
events. The page is plain HTML, CSS and JavaScript with no build step, and
the charts are hand-drawn SVG.

## Two things the UI work uncovered

1. **An intermittent crash in policy enforcement (fixed).** The smoke test
   failed now and then on a Phase 5 check, with a Go runtime crash inside
   `minibox init`. The cause was in Phase 4/5 code. The seccomp filter was
   installed with `unix.Syscall`, which returns through the Go scheduler,
   and the scheduler sometimes calls `futex`. Under a policy without
   `futex`, that call was denied and the runtime died before `execve`:
   7 of 150 runs on the old code. Now the filter and `execve` are two
   back-to-back raw syscalls with nothing in between
   (`security.ExecLocked`): 0 of 300 runs crashed. A smoke check keeps it
   that way. The benchmarks were not affected, because `bench/run.py`
   fails on any non-zero exit.
2. **PID 1 ignores SIGTERM.** The first CPU demo ran `timeout 6 sh -c 'while :; do :; done'`
   as the container's command. busybox `timeout` execs the command itself,
   so the loop became PID 1, which the kernel protects from signals it has
   no handler for. It never stopped. The demo now keeps a shell as PID 1.
   It's the same reason Docker has `--init`.

## Tests

- Unit tests (`internal/ui/ui_test.go`): parameter validation, the Host and
  header checks, the filter endpoint, cgroup file parsing, attack outcome
  parsing.
- Profiler events (`internal/profile/events_test.go`) and the disassembler
  and evaluator (`internal/security/disasm_test.go`, cross-checked against
  the test interpreter).
- 12 smoke checks under "Phase 8" in `tests/smoke.sh`. They start the real
  server and run the isolation, memory and profile demos.
- `tests/ui/check_ui.py` (optional, needs Playwright): clicks through every
  panel in a headless browser, takes screenshots in light and dark mode,
  and fails on any JavaScript error.

## Where the code is

| File | What it does |
|---|---|
| `cmd/minibox/ui.go` | `minibox ui` flags, listener, clean shutdown |
| `internal/ui/server.go` | Routes, safety checks, `/api/info`, `/api/filter`, job start/stop |
| `internal/ui/actions.go` | The catalogue: every demo and the commands it runs |
| `internal/ui/jobs.go` | Runs a minibox child process, streams output, stops it gently |
| `internal/ui/cgwatch.go` | Finds the container's cgroup and samples it |
| `internal/ui/hub.go` | Server-sent events to every open page |
| `internal/ui/isolation.go` | Host and container facts for Phase 1 |
| `internal/ui/static/` | The page (HTML, CSS, JS), embedded in the binary |
| `internal/profile/events.go` | `--events` live log |
| `internal/security/disasm.go` | BPF disassembler and evaluator |
| `tools/bpfdump`, `scripts/build-explainer.py` | Data for the explainer |
| `docs/explainer.html` | The explainer page |
