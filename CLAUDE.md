# minibox: project instructions

You are helping me build a college Operating Systems course project from scratch to finish. I'm a CS student on a 3-person team, and I need to understand and explain every part of this in a viva, so write clear code, document as you go, and explain key decisions briefly in commit messages and docs.

## Project
"minibox": a rootless Linux container runtime written in Go, plus an automatic least-privilege hardening feature that I will evaluate with an attack test suite and benchmarks.

## Environment
- Ubuntu Server 26.04.1 LTS VM in VirtualBox, kernel 7.0.0-38-generic, cgroups v2 enabled.
- I have set kernel.apparmor_restrict_unprivileged_userns=0 so rootless user namespaces work.
- Everything runs inside this VM. Never assume host access.
- Go 1.27.3 (linux/amd64). Use only the Go standard library plus golang.org/x/sys/unix and well-known libraries (e.g. libseccomp-golang, cilium/ebpf if needed). Ask before adding any other dependency.

## Progress tracking
- Keep docs/PROGRESS.md up to date: current phase, what's done, what's next, and any open issues.
- At the start of every session, read docs/PROGRESS.md and continue from where it says, instead of starting over.

## Goals, in phases
Work phase by phase. At the end of each phase: make sure it builds, add tests, update the README and docs/PROGRESS.md, commit, then STOP and give me a short summary of what was built, how to run it, and what I should understand before moving on. Wait for my go-ahead before starting the next phase.

Phase 0: Setup
- Check the environment (kernel version, cgroups v2, user namespaces enabled, overlayfs available) with a script `scripts/check-env.sh` that reports problems clearly.
- Set up the repo: Go module, Makefile, cmd/minibox, internal/ packages, docs/, tests/, a .gitignore, and a README skeleton.
- Write a script to download and unpack an Alpine minirootfs into ./images/alpine (images/ should be git-ignored).

Phase 1: Isolation (namespaces + filesystem)
- `minibox run <rootfs> <cmd> [args...]`
- New PID, mount, UTS, IPC and user namespaces (rootless: map container root to my user).
- overlayfs: rootfs as read-only lower layer, per-container upper/work dirs.
- pivot_root into the new root, mount a fresh /proc, set hostname.
- Clean up mounts and directories when the container exits.

Phase 2: Resource limits (cgroups v2)
- Flags: --memory, --cpus, --pids.
- Create a cgroup per container, apply limits, remove it on exit.
- Tests that prove each limit works (memory hog gets killed, fork bomb is capped, CPU-bound task is throttled).

Phase 3: Networking
- Network namespace with a veth pair to the host, IP assignment, and optional outbound access via NAT.
- Flag --net=none|bridge. Document any step that needs root and why (rootless networking may need slirp4netns or similar; explain the tradeoff and pick the simplest working option).

Phase 4: Baseline security
- Drop all capabilities except a documented default set.
- Apply a default seccomp profile modeled on Docker's default.
- Mask/read-only sensitive paths (/proc/sys, /proc/sysrq-trigger, /sys/firmware, etc.).
- No-new-privileges flag set.

Phase 5: Profiling mode (the novel part)
- `minibox profile <rootfs> <cmd>` runs the app and records every syscall, capability check, and file path accessed (written vs read). Use eBPF if feasible on my kernel, otherwise ptrace/strace-based tracing; explain the choice.
- Output a policy file (JSON): syscall allowlist, minimal capability set, writable paths.
- `minibox run --policy policy.json ...` enforces it: seccomp allowlist (default deny), only listed capabilities, everything not in writable paths mounted read-only.

Phase 6: Evaluation
- tests/attacks/: a suite of at least 10 benign, self-contained container-escape and abuse attempts that are safe to run inside the VM (e.g. calling mount, ptrace on another process, loading a kernel module, unshare to regain privileges, writing to masked /proc paths, fork bomb, memory exhaustion, raw sockets, changing hostname/time, reading other containers' files). These are misconfiguration and policy tests, not real CVE exploits.
- Run each attack under three configs: no hardening, baseline (Phase 4), and auto-generated policy (Phase 5). Produce a results table as Markdown and CSV.
- Benchmarks with 2-3 real workloads (e.g. a small Python HTTP server, nginx or busybox httpd, a CPU-bound script): startup time, throughput/latency, and overhead of each config. Repeat runs, report mean and std dev.
- Compare syscall counts: Docker default profile size vs our generated profile per workload.
- Never invent or estimate numbers. Every number in the docs must come from a script in the repo that I can re-run.

Phase 7: Write-up
- README: what it is, architecture diagram (Mermaid), quick start, demo commands, results tables, limitations, related work (Docker/runc, Bocker, Liz Rice's "Containers From Scratch", Red Hat oci-seccomp-bpf-hook, SlimToolkit) and how ours differs.
- docs/how-it-works.md: plain-language explanation of each OS concept used (namespaces, cgroups, overlayfs, pivot_root, capabilities, seccomp, eBPF/ptrace) and where it lives in our code.
- docs/viva-prep.md: 20 likely examiner questions with short answers.
- A suggested split of the codebase among 3 team members.

## Rules
- Small, readable functions; comments that explain *why*, not just what.
- Commit after each meaningful step with descriptive messages.
- If something fails because of my kernel or VM config, stop and tell me exactly what to change rather than working around it silently.
- If you're unsure about a design choice, give me 2 options with tradeoffs and ask.
- Do not run anything outside the VM or anything destructive to the VM without asking.
