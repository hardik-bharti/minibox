# minibox

A rootless Linux container runtime written in Go, with an automatic
least-privilege hardening mode: `minibox profile` traces what an application
actually does and generates a policy, and `minibox run --policy` enforces it.

Built as an Operating Systems course project. It covers namespaces, cgroups v2,
overlayfs, pivot_root, capabilities, seccomp and syscall tracing.

> **Status:** Phase 0 (setup) is done. The `run` and `profile` commands are
> stubs for now. See [docs/PROGRESS.md](docs/PROGRESS.md).

## Requirements

- Linux kernel >= 5.11 with cgroups v2 and unprivileged user namespaces
  (developed on Ubuntu 26.04.1, kernel 7.0)
- Go 1.27+
- No root needed for the core runtime

`make check-env` verifies all of these and says how to fix anything missing.

## Quick start

```sh
make check-env   # verify kernel/VM features
make image       # download Alpine minirootfs into images/alpine
make build       # build bin/minibox
make test        # unit tests
make smoke       # end-to-end checks in this VM
```

## Repository layout

| Path | Purpose |
|------|---------|
| `cmd/minibox/` | CLI entry point and subcommand dispatch |
| `internal/container/` | Namespaces, overlayfs, pivot_root (Phase 1) |
| `internal/cgroups/` | Resource limits via cgroups v2 (Phase 2) |
| `internal/network/` | Network namespace and veth setup (Phase 3) |
| `internal/security/` | Capabilities, seccomp, masked paths (Phase 4) |
| `internal/profile/` | Tracing and policy generation (Phase 5) |
| `scripts/` | Environment check and image download |
| `tests/` | VM-level tests; attack suite comes in Phase 6 |
| `docs/` | Progress log and design docs |

## Usage

*(Filled in as features land.)*

## Architecture

*(Diagram added in Phase 7.)*

## Evaluation

*(Attack suite and benchmark results from Phase 6.)*

## Limitations

*(Phase 7.)*

## Related work

*(Phase 7: Docker/runc, Bocker, "Containers From Scratch", oci-seccomp-bpf-hook,
SlimToolkit.)*
