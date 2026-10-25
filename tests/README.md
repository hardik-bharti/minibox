# tests

Unit tests live next to the code they test (`*_test.go`, run with `make test`).
This directory holds tests that need the real VM:

| Path | What it checks | Run with |
|------|----------------|----------|
| `smoke.sh` | Setup and end-to-end sanity checks; grows with each phase | `make smoke` |
| `attacks/` *(Phase 6)* | Container escape/abuse attempts run under each hardening config | (Phase 6) |
