#!/usr/bin/env bash
# get-alpine.sh: download and unpack the Alpine minirootfs into images/alpine.
#
# We read Alpine's release index (latest-releases.yaml) instead of hard-coding
# a version, so the script keeps working when Alpine ships a new release. The
# same index gives us the SHA-256, which we verify before unpacking anything.
#
# Usage: scripts/get-alpine.sh [dest-dir]   (default: images/alpine)

set -euo pipefail

ARCH=x86_64
MIRROR=${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}
BASE="$MIRROR/latest-stable/releases/$ARCH"

repo_root=$(cd "$(dirname "$0")/.." && pwd)
dest=${1:-"$repo_root/images/alpine"}

fetch() { # fetch URL OUTFILE
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
    else
        wget -q -O "$2" "$1"
    fi
}

if [ -e "$dest/bin/busybox" ]; then
    echo "Alpine rootfs already present at $dest (delete it to re-download)"
    exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Fetching release index from $BASE"
fetch "$BASE/latest-releases.yaml" "$tmp/index.yaml"

# The index is a YAML list of entries, each starting with a "-" line. Collect
# file/sha256/flavor per entry and print the pair for the minirootfs flavor.
# A full YAML parser is overkill for this flat format.
read -r file sum < <(awk '
    function emit() { if (flavor == "alpine-minirootfs") { print file, sum; exit } }
    /^-/              { emit(); flavor = file = sum = "" }
    $1 == "flavor:"   { flavor = $2 }
    $1 == "file:"     { file = $2 }
    $1 == "sha256:"   { sum = $2 }
    END               { emit() }
' "$tmp/index.yaml") || true
if [ -z "$file" ] || [ -z "$sum" ]; then
    echo "error: could not find minirootfs entry in release index" >&2
    exit 1
fi

echo "Downloading $file"
fetch "$BASE/$file" "$tmp/$file"

echo "Verifying SHA-256"
echo "$sum  $tmp/$file" | sha256sum -c --quiet -

# Unpack into a staging dir first, then rename, so an interrupted run never
# leaves a half-extracted image that looks valid.
mkdir -p "$(dirname "$dest")"
stage="$dest.partial"
rm -rf "$stage"
mkdir -p "$stage"
# --no-same-owner: we are unprivileged, so files are owned by us. Inside the
# container's user namespace our UID maps to root, so they appear root-owned.
tar -xzf "$tmp/$file" -C "$stage" --no-same-owner
mv "$stage" "$dest"

echo "Alpine $(cat "$dest/etc/alpine-release") unpacked to $dest"
