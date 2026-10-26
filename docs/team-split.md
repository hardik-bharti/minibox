# Suggested split among 3 team members

Each person owns a vertical slice: code, tests, docs and the viva
questions about it. Everyone should still be able to explain the
end-to-end flow (`docs/how-it-works.md`), because examiners often ask
about another member's part.

| | Member A: Isolation & resources | Member B: Network & security | Member C: Profiling & evaluation |
|---|---|---|---|
| Phases | 1, 2 (+0) | 3, 4 | 5, 6 |
| Code | `internal/container/` (namespaces, overlay, `/dev`, `/proc`, `/sys`, pivot_root, volumes, exec), `internal/cgroups/`, `cmd/minibox/` flag parsing and the systemd-run re-exec | `internal/network/` (loopback ioctl, slirp4netns, ports), `internal/security/` caps, seccomp compiler, Docker profile, masked paths | `internal/profile/` (ptrace tracer, recorder, capability inference, merge), policy enforcement in `security/apply.go` + `policy.go`, `tests/attacks/`, `bench/`, `tools/` |
| Tests | `tests/smoke.sh` Phases 0-2, `internal/container/*_test.go`, `internal/cgroups/*_test.go` | smoke Phases 3-4, `internal/network/*_test.go`, `internal/security/*_test.go` (the BPF interpreter) | smoke Phase 5, `internal/profile/*_test.go`, `make attacks`, `make bench` |
| Docs | `phase1-isolation.md`, `phase2-cgroups.md`, `scripts/check-env.sh` | `phase3-networking.md`, `phase4-security.md` | `phase5-profiling.md`, results write-up in README |
| Viva questions (`viva-prep.md`) | 1-7 | 8-12 | 13-20 |
| Demo to prepare | namespaces (`readlink /proc/self/ns/*`), overlay copy-on-write, memory hog OOM-killed | `--net bridge` + `-p`, CapEff/Seccomp in `/proc/self/status`, `mount` allowed under `--security none` but blocked by baseline | profile a server, run it under `--policy`, show `hostname` failing, run `make attacks` |

Shared work: README, `how-it-works.md`, rehearsing the full demo, and reading
each other's phase docs before the viva.

The demo dashboard (`minibox ui`, Phase 8) follows the same split: each
member presents their own panels. A: Isolation and Resource limits. B:
Inside the filter. C: Profile and enforce, and the Attack suite. Member C
owns the server code (`internal/ui/`).

Rough size of each slice, so the split is fair: run
`wc -l internal/*/*.go cmd/minibox/*.go tests/attacks/probe/*.go tools/*/*.go`
to see the line counts per package. Each slice is a similar mix of
OS-level code and tests.
