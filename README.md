# minibox

A rootless Linux container runtime written in Go, with an automatic
least-privilege hardening mode: `minibox profile` traces what an application
actually does and generates a policy, and `minibox run --policy` enforces it.

Built as an Operating Systems course project. It covers namespaces, cgroups v2,
overlayfs, pivot_root, capabilities, seccomp and syscall tracing.

> **Status:** Phase 1 (isolation) done: `minibox run` works. Resource limits,
> networking and hardening are next. See [docs/PROGRESS.md](docs/PROGRESS.md).

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
| `internal/container/` | Namespaces, overlayfs, /dev, /proc, pivot_root (Phase 1) |
| `internal/cgroups/` | Resource limits via cgroups v2 (Phase 2) |
| `internal/network/` | Network namespace and veth setup (Phase 3) |
| `internal/security/` | Capabilities, seccomp, masked paths (Phase 4) |
| `internal/profile/` | Tracing and policy generation (Phase 5) |
| `scripts/` | Environment check and image download |
| `tests/` | VM-level tests; attack suite comes in Phase 6 |
| `docs/` | Progress log and design docs |

## Usage

```sh
# Interactive shell in an Alpine container (no sudo)
./bin/minibox run images/alpine /bin/sh

# One-off command with a custom hostname
./bin/minibox run --hostname box1 images/alpine sh -c 'hostname; id; ps'
```

Flags go **before** the rootfs. Everything after the command belongs to the
command.

| Flag | Meaning |
|------|---------|
| `--hostname NAME` | Container hostname (default: the container ID) |

Each container gets new user, PID, mount, UTS and IPC namespaces, and an
overlayfs root on top of the image, so the image is never modified. Inside,
you are root (UID 0), but that maps to your own user on the host. Writes are
discarded when the container exits.

Exit status: the command's own exit code, `128+N` if it was killed by
signal N, or `127` if minibox couldn't set up the container. Ctrl-C is
forwarded to the container. Press it again to force-kill.

Container state lives in `~/.local/share/minibox/containers/<id>` while it
runs (override with `MINIBOX_ROOT`) and is deleted on exit.

How it works, step by step: [docs/phase1-isolation.md](docs/phase1-isolation.md).

## Architecture

*(Diagram added in Phase 7.)*

## Evaluation

*(Attack suite and benchmark results from Phase 6.)*

## Limitations

*(Phase 7.)*

## Related work

*(Phase 7: Docker/runc, Bocker, "Containers From Scratch", oci-seccomp-bpf-hook,
SlimToolkit.)*
