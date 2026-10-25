#!/usr/bin/env python3
"""Copy the generated result tables into README.md and docs/phase6-evaluation.md.

The tables are produced by tests/attacks/run.py and bench/run.py into
results/*.md. Docs contain marker pairs such as

    <!-- results:attacks-matrix -->
    ...replaced...
    <!-- /results:attacks-matrix -->

and this script replaces what is between them, so numbers in the docs are
always exactly the ones the scripts produced. Run after `make attacks` and
`make bench` (both Makefile targets call it).
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
DOCS = [ROOT / "README.md", ROOT / "docs" / "phase6-evaluation.md"]


def tables(md):
    """Split markdown into its tables (blocks of lines starting with '|')."""
    blocks, cur = [], []
    for line in md.splitlines():
        if line.startswith("|"):
            cur.append(line)
        elif cur:
            blocks.append("\n".join(cur))
            cur = []
    if cur:
        blocks.append("\n".join(cur))
    return blocks


def blocks():
    attacks = (RESULTS / "attacks.md").read_text()
    att_tables = tables(attacks.split("## Details")[0])
    bench = (RESULTS / "bench.md").read_text()
    bench_intro = [l for l in bench.splitlines() if l.startswith(("Environment:", "Startup has", "Cells:"))]
    return {
        "attacks-matrix": att_tables[0],
        "attacks-summary": att_tables[1],
        "bench": "\n\n".join(bench_intro + tables(bench)),
        "syscalls": (RESULTS / "syscalls.md").read_text().strip(),
    }


def main():
    content = blocks()
    for doc in DOCS:
        if not doc.exists():
            continue
        text = doc.read_text()
        for name, body in content.items():
            pattern = re.compile(rf"(<!-- results:{name} -->\n).*?(<!-- /results:{name} -->)", re.S)
            text = pattern.sub(lambda m: m.group(1) + body + "\n" + m.group(2), text)
        doc.write_text(text)
        print(f"updated {doc.relative_to(ROOT)}")


if __name__ == "__main__":
    sys.exit(main())
