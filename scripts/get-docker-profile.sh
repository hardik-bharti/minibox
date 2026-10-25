#!/usr/bin/env bash
# get-docker-profile.sh: (re)download Docker's default seccomp profile into
# internal/security/profiles/docker-default.json.
#
# minibox's baseline seccomp filter (Phase 4) is compiled from this file,
# and Phase 6 compares its size with our generated policies. It is pinned
# to a fixed commit and checksum so results are reproducible.
# Source: github.com/moby/profiles, tag seccomp/v0.2.4 (Apache-2.0).
set -euo pipefail
cd "$(dirname "$0")/.."

commit=245180c51918481c0525424b3ee025d2b435d46c
sha256=785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334
url=https://raw.githubusercontent.com/moby/profiles/$commit/seccomp/default.json
out=internal/security/profiles/docker-default.json

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL -o "$tmp" "$url"
echo "$sha256  $tmp" | sha256sum -c --quiet
mv "$tmp" "$out"
echo "wrote $out (moby/profiles@${commit:0:12})"
