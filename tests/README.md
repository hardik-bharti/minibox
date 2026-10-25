# tests

Unit tests live next to the code they test (`*_test.go`, run with `make test`).
This directory holds tests that need the real VM:

| Path | What it checks | Run with |
|------|----------------|----------|
| `smoke.sh` | Setup and end-to-end sanity checks; grows with each phase | `make smoke` |
| `attacks/probe/` | One static Go binary, one subcommand per attack (17 attacks), mounted read-only at `/probe` | built by `run.py` |
| `attacks/run.py` | Runs every attack under `none`, `baseline` and `policy`; writes `results/attacks.{csv,md}` | `make attacks` |

Benchmarks live in `bench/run.py` (`make bench`). Results are in `results/`.
