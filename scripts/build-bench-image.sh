#!/usr/bin/env bash
# build-bench-image.sh: make images/bench = Alpine + python3 + busybox-extras
# (for busybox httpd). Used by the Phase 6 benchmarks and attack suite.
#
# minibox's overlay throws away everything a container writes, so we can't
# just run `apk add` in a container. Instead we copy the base image, mount
# the copy into a throwaway Alpine container with -v, and let apk install
# into it with --root. No root needed: inside the container we are UID 0,
# which maps to our own user, and every file apk creates belongs to us.
#
# Usage: scripts/build-bench-image.sh    (needs images/alpine and slirp4netns)
set -euo pipefail
cd "$(dirname "$0")/.."

base=images/alpine
dest=images/bench
packages="python3 busybox-extras"

[ -x "$base/bin/busybox" ] || { echo "missing $base: run 'make image' first" >&2; exit 1; }
[ -x bin/minibox ] || { echo "missing bin/minibox: run 'make build' first" >&2; exit 1; }

rm -rf "$dest.tmp"
cp -a "$base" "$dest.tmp"
# --security none: apk needs chown/chmod freely while installing.
bin/minibox run --security none --net bridge -v "$PWD/$dest.tmp:/target" "$base" \
    apk --root /target --no-cache --quiet add $packages
rm -rf "$dest"
mv "$dest.tmp" "$dest"
echo "built $dest with: $(bin/minibox run --security none "$dest" sh -c 'python3 --version; busybox-extras 2>&1 | head -1')"
