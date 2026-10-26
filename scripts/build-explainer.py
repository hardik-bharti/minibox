#!/usr/bin/env python3
"""Fill the data block of docs/explainer.html from the repository.

Usage: scripts/build-explainer.py      (or: make explainer)

The explainer is a single HTML page (published as a claude.ai artifact and
kept in the repo). Its numbers and instructions are never typed in by hand:

  - seccomp programs and syscall paths: `go run ./tools/bpfdump`, for the
    generated attack-suite policy and for Docker's baseline
  - attack results: results/attacks.csv (written by tests/attacks/run.py)
  - syscall counts: results/syscalls.csv (written by bench/run.py)

They are inserted between the <!-- explainer-data --> markers as JSON.
"""

import csv
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "explainer.html"
POLICY = "results/policies/attack-probe.json"
# Syscalls to trace through both filters. clone is traced twice by bpfdump
# (an ordinary fork, and CLONE_NEWUSER).
TRACE = "write,getpid,openat,socket,mount,ptrace,unshare,clone,clone3,init_module,reboot"


def bpfdump(*args):
    r = subprocess.run(["go", "run", "./tools/bpfdump", "-trace", TRACE, *args],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"bpfdump {' '.join(args)} failed:\n{r.stderr}")
    return json.loads(r.stdout)


def read_csv(name):
    with open(ROOT / "results" / name, newline="") as f:
        return list(csv.DictReader(f))


def main():
    for f in (ROOT / POLICY, ROOT / "results" / "attacks.csv", ROOT / "results" / "syscalls.csv"):
        if not f.exists():
            sys.exit(f"missing {f.relative_to(ROOT)}: run `make attacks` and `make bench` first")
    data = {
        "filters": {"policy": bpfdump("-policy", POLICY), "baseline": bpfdump("-baseline")},
        "attacks": read_csv("attacks.csv"),
        "syscalls": read_csv("syscalls.csv"),
        "sources": {
            "filters": f"go run ./tools/bpfdump -trace {TRACE} (-policy {POLICY} | -baseline)",
            "attacks": "results/attacks.csv (tests/attacks/run.py)",
            "syscalls": "results/syscalls.csv (bench/run.py, tools/policystats)",
        },
    }
    # "</" must not appear inside a <script> block.
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    block = f'<script id="explainer-data" type="application/json">{blob}</script>'
    page = PAGE.read_text()
    pattern = re.compile(r"(<!-- explainer-data -->\n).*?(\n<!-- /explainer-data -->)", re.S)
    if not pattern.search(page):
        sys.exit(f"{PAGE.relative_to(ROOT)} has no <!-- explainer-data --> markers")
    PAGE.write_text(pattern.sub(lambda m: m.group(1) + block + m.group(2), page))
    print(f"updated {PAGE.relative_to(ROOT)} ({len(blob) // 1024} KiB of data)")


if __name__ == "__main__":
    main()
