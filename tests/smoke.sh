#!/usr/bin/env bash
# smoke.sh: end-to-end sanity checks that need the real VM, not just `go test`.
#
# Phase 0 checks only the setup: scripts parse, the environment check passes,
# and the Alpine image is usable inside a rootless user namespace. Later
# phases add checks that run real containers through bin/minibox.

set -euo pipefail
cd "$(dirname "$0")/.."

ok() { printf '  ok   %s\n' "$1"; }

for s in scripts/*.sh tests/*.sh; do
    bash -n "$s"
done
ok "all shell scripts parse"

scripts/check-env.sh >/dev/null
ok "check-env.sh reports no failures"

if [ ! -x images/alpine/bin/busybox ]; then
    echo "  FAIL images/alpine missing; run 'make image' first" >&2
    exit 1
fi
out=$(unshare --user --map-root-user chroot images/alpine /bin/sh -c 'id -u')
[ "$out" = "0" ]
ok "Alpine rootfs runs a shell as uid 0 inside a user namespace"

echo "smoke tests passed"
