# minibox

A rootless Linux container runtime written in Go, with an automatic
least-privilege hardening mode: `minibox profile` traces what an application
actually does and generates a policy, and `minibox run --policy` enforces it.

Built as an Operating Systems course project. It covers namespaces, cgroups v2,
overlayfs, pivot_root, capabilities, seccomp and syscall tracing.

> **Status:** Phases 1 (isolation), 2 (resource limits) and 3 (networking) done. See [docs/PROGRESS.md](docs/PROGRESS.md).

## Requirements

- Linux kernel >= 5.11 with cgroups v2 and unprivileged user namespaces
  (developed on Ubuntu 26.04.1, kernel 7.0)
- Go 1.27+
- No root needed for the core runtime
- Optional: `slirp4netns` for `--net=bridge` (`sudo apt install slirp4netns`)

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
| `internal/network/` | Network namespace, loopback, slirp4netns outbound access and port publishing (Phase 3) |
| `internal/security/` | Capabilities, seccomp, masked paths (Phase 4) |
| `internal/profile/` | Tracing and policy generation (Phase 5) |
| `scripts/` | Environment check, image download, CPU-throttle repro |
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
| `--memory SIZE` | Memory limit, e.g. `64m`, `1g`; swap disabled; exceeding it gets the process OOM-killed |
| `--cpus N` | CPU limit in CPUs, e.g. `0.5` |
| `--pids N` | Max processes+threads (minimum 8) |
| `--stats` | Print cgroup resource usage to stderr on exit |
| `--net none\|bridge` | `none` (default): loopback only. `bridge`: IP 10.0.3.100, DNS and outbound access via slirp4netns |
| `-p HOST:CONTAINER[/udp]` | Publish a port (needs `--net bridge`, repeatable) |

```sh
./bin/minibox run --memory 50m --pids 20 --stats images/alpine sh
```

Limits use cgroups v2 inside a delegated systemd user scope. minibox starts
one automatically via `systemd-run --user --scope`. See
[docs/phase2-cgroups.md](docs/phase2-cgroups.md).

Each container gets new user, PID, mount, UTS, IPC and network namespaces, and an
overlayfs root on top of the image, so the image is never modified. Inside,
you are root (UID 0), but that maps to your own user on the host. Writes are
discarded when the container exits.

Exit status: the command's own exit code, `128+N` if it was killed by
signal N, or `127` if minibox couldn't set up the container. Ctrl-C is
forwarded to the container. Press it again to force-kill.

Container state lives in `~/.local/share/minibox/containers/<id>` while it
runs (override with `MINIBOX_ROOT`) and is deleted on exit.

```sh
# Networking: none by default; bridge gives rootless outbound access
./bin/minibox run --net bridge images/alpine wget -qO- http://example.com
./bin/minibox run --net bridge -p 8080:80 images/alpine nc -l -p 80 -e echo hi
```

Every container gets its own network namespace. With `--net bridge`,
[slirp4netns](https://github.com/rootless-containers/slirp4netns) gives it a
`tap0` interface and NATs its traffic in user space, so no root is needed.
Docs: [docs/phase3-networking.md](docs/phase3-networking.md) explains why
this was chosen over a veth pair plus bridge and iptables, which needs root.

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
