#!/usr/bin/env python3
"""Phase 6 benchmarks: overhead of each hardening configuration.

Usage: bench/run.py [--reps N] [--duration SECONDS] [--quick]

Workloads (all in images/bench, from scripts/build-bench-image.sh):
  startup      `minibox run <img> true`: container start + teardown time
  python-http  python3 -m http.server, driven by tools/loadgen through -p
               (one client, see CONCURRENCY)
  busybox-http busybox httpd, driven the same way
  cpu-python   a CPU-bound Python loop (wall time of the whole container run)
  syscall-dd   dd with 1-byte blocks: ~1M read/write syscalls, a worst case
               for per-syscall seccomp cost

Configurations: none (--security none), baseline (default), policy
(--policy results/policies/<workload>.json, generated here by profiling
the same workload). No resource limits in any config, so only security
overhead is compared. HTTP workloads use --net bridge (slirp4netns) in
every config.

Each (workload, config) pair is repeated --reps times, in interleaved
order (none, baseline, policy, none, ...) so slow drift in the VM affects
all configs alike. Results: results/bench.csv (every run) and
results/bench.md (mean and sample standard deviation), plus the syscall
count comparison in results/syscalls.{csv,md}. Nothing is estimated: every
number comes from a run of this script.
"""

import argparse
import csv
import json
import os
import platform
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MINIBOX = ROOT / "bin" / "minibox"
IMAGE = ROOT / "images" / "bench"
ALPINE = ROOT / "images" / "alpine"
RESULTS = ROOT / "results"
POLICIES = RESULTS / "policies"
LOADGEN = ROOT / "bin" / "loadgen"
CONFIGS = ["none", "baseline", "policy"]

CPU_SCRIPT = "s=0\nfor i in range(6_000_000): s += i*i\nprint(s)"
DD = ["dd", "if=/dev/zero", "of=/dev/null", "bs=1", "count=500000"]

port_counter = [18400]


def next_port():
    port_counter[0] += 1
    return port_counter[0]


def config_flags(config, workload):
    if config == "none":
        return ["--security", "none"]
    if config == "policy":
        return ["--policy", str(POLICIES / f"{workload}.json")]
    return []


# --- servers -----------------------------------------------------------

SERVERS = {
    # container command, container port, URL path
    "python-http": (["python3", "-m", "http.server", "8000", "-d", "/srv"], 8000),
    "busybox-http": (["httpd", "-f", "-p", "8000", "-h", "/srv"], 8000),
}

# A small static file served by both servers. Written through a volume so
# both servers serve identical bytes and the image stays unchanged.
SRV_DIR = RESULTS / ".srv"


def prepare_srv():
    SRV_DIR.mkdir(parents=True, exist_ok=True)
    (SRV_DIR / "index.html").write_text("<html><body>" + "minibox " * 128 + "</body></html>\n")


class Server:
    """A server container on a fresh host port, run or profiled."""

    def __init__(self, workload, args, mode="run"):
        cmd, cport = SERVERS[workload]
        self.port = next_port()
        self.url = f"http://127.0.0.1:{self.port}/index.html"
        # Output goes to a file, not a pipe: http.server logs every
        # request, and an unread pipe fills up and blocks the server.
        self.log = tempfile.TemporaryFile(mode="w+")
        self.proc = subprocess.Popen(
            [str(MINIBOX), mode] + args +
            ["--net", "bridge", "-p", f"{self.port}:{cport}", "-v", f"{SRV_DIR}:/srv:ro", str(IMAGE)] + cmd,
            stdout=self.log, stderr=subprocess.STDOUT, text=True)
        self.wait_ready()

    def wait_ready(self):
        for _ in range(300):
            if self.proc.poll() is not None:
                raise RuntimeError(f"server exited: {self.output()}")
            try:
                urllib.request.urlopen(self.url, timeout=1).read()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("server did not become ready")

    def stop(self):
        # SIGINT: minibox forwards it, both servers exit cleanly on it,
        # and `minibox profile` then writes its policy.
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.send_signal(signal.SIGINT)  # second signal = SIGKILL
            self.proc.wait()
        return self.output()

    def output(self):
        self.log.seek(0)
        text = self.log.read()
        self.log.close()
        return text


# One client at a time: both servers have tiny listen backlogs (Python's
# socketserver uses 5), so with several concurrent clients some connection
# attempts are dropped and retried by TCP after ~1 s. We measured those
# outliers even with the server running directly on the host, so they say
# nothing about containers; at concurrency 1 they disappear.
CONCURRENCY = 1


def loadgen(url, duration, conc=CONCURRENCY):
    r = subprocess.run([str(LOADGEN), "-url", url, "-c", str(conc), "-d", f"{duration}s"],
                       capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


# --- profiling ---------------------------------------------------------

def profile_all(duration):
    POLICIES.mkdir(parents=True, exist_ok=True)
    for w in ["startup", "cpu-python", "syscall-dd", "python-http", "busybox-http"]:
        out = POLICIES / f"{w}.json"
        out.unlink(missing_ok=True)
        for _ in range(2):  # merge two runs for better coverage
            args = ["--merge", "-o", str(out)]
            if w in SERVERS:
                s = Server(w, args, mode="profile")
                loadgen(s.url, max(2, duration // 3))
                s.stop()
            else:
                subprocess.run([str(MINIBOX), "profile"] + args + [str(image_for(w))] + command_for(w),
                               check=True, capture_output=True)
        pol = json.loads(out.read_text())
        print(f"  policy {w}: {len(pol['syscalls'])} syscalls, caps {pol['capabilities']}, "
              f"writable {pol['writable_paths']}")


def image_for(w):
    return ALPINE if w == "startup" else IMAGE


def command_for(w):
    return {"startup": ["true"], "cpu-python": ["python3", "-c", CPU_SCRIPT], "syscall-dd": DD}[w]


# --- measurements ------------------------------------------------------

def time_run(w, config):
    cmd = [str(MINIBOX), "run"] + config_flags(config, w) + [str(image_for(w))] + command_for(w)
    t = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.perf_counter() - t
    if r.returncode != 0:
        raise RuntimeError(f"{w}/{config} failed ({r.returncode}): {r.stderr[-300:]}")
    return elapsed


def bench_timed(w, reps, rows, metric):
    for config in CONFIGS:  # unmeasured warm-up: page cache, first-run effects
        time_run(w, config)
    for rep in range(reps):
        for config in CONFIGS:
            rows.append(dict(workload=w, config=config, rep=rep, metric=metric,
                             value=round(time_run(w, config) * 1000, 3), unit="ms"))


def bench_http(w, reps, duration, rows):
    for rep in range(reps):
        for config in CONFIGS:
            s = Server(w, config_flags(config, w))  # loadgen warms up 1 s itself
            try:
                res = loadgen(s.url, duration)
            finally:
                s.stop()
            if res["errors"]:
                print(f"  warning: {w}/{config} rep {rep}: {res['errors']} errors")
            for metric, unit in [("rps", "req/s"), ("lat_mean_ms", "ms"), ("lat_p50_ms", "ms"),
                                 ("lat_p99_ms", "ms"), ("slow_over_500ms", "requests")]:
                rows.append(dict(workload=w, config=config, rep=rep, metric=metric,
                                 value=round(res[metric], 3), unit=unit))


# --- reporting ---------------------------------------------------------

def summarize(rows):
    groups = {}
    for r in rows:
        groups.setdefault((r["workload"], r["metric"], r["unit"]), {}).setdefault(r["config"], []).append(r["value"])
    return groups


def fmt(vals):
    m = statistics.mean(vals)
    sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
    return m, sd, statistics.median(vals)


META = RESULTS / "bench-meta.json"


def write_csv(rows, reps, duration):
    with open(RESULTS / "bench.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    META.write_text(json.dumps({
        "env": (f"{platform.node()}, kernel {platform.release()}, {os.cpu_count()} vCPUs, "
                f"{time.strftime('%Y-%m-%d %H:%M %Z')}"),
        "reps": reps, "duration": duration}, indent=2) + "\n")


def write_report():
    """Write results/bench.md from results/bench.csv (no measuring)."""
    meta = json.loads(META.read_text())
    reps, duration, env = meta["reps"], meta["duration"], meta["env"]
    with open(RESULTS / "bench.csv") as f:
        rows = [dict(r, value=float(r["value"])) for r in csv.DictReader(f)]
    out = ["# Benchmark results", "",
           "Generated by `bench/run.py`. Do not edit by hand.", "",
           f"Environment: {env}. Repetitions per cell: {reps}"
           f" (HTTP: {duration} s of load each after 1 s warm-up, {CONCURRENCY} client, new connection per request,"
           " through slirp4netns in every config).", "",
           f"Startup has {reps * 6} repetitions per cell (it is cheap).", "",
           "Cells: mean ± sample standard deviation, then the median. *Overhead* compares "
           "each configuration with `none`, by mean and by median (positive = worse: slower, "
           "or fewer requests/s). The median is less sensitive to a single slow run.", "",
           "| Workload | Metric | none | baseline | policy | baseline overhead (mean / median) | policy overhead (mean / median) |",
           "|---|---|---|---|---|---|---|"]
    higher_is_better = {"rps"}
    for (w, metric, unit), by in summarize(rows).items():
        if metric == "slow_over_500ms":
            continue  # kept in the CSV as a sanity check; should be 0
        cells, means, medians = [], {}, {}
        for c in CONFIGS:
            m, sd, med = fmt(by[c])
            means[c], medians[c] = m, med
            cells.append(f"{m:.2f} ± {sd:.2f} (med {med:.2f})")

        def delta(stat, c):
            d = (stat[c] - stat["none"]) / stat["none"] * 100
            return -d if metric in higher_is_better else d
        over = [f"{delta(means, c):+.1f}% / {delta(medians, c):+.1f}%" for c in ["baseline", "policy"]]
        out.append(f"| {w} | {metric} ({unit}) | " + " | ".join(cells) + " | " + " | ".join(over) + " |")
    (RESULTS / "bench.md").write_text("\n".join(out) + "\n")


def syscall_compare():
    policies = sorted(str(p) for p in POLICIES.glob("*.json"))
    subprocess.run(["go", "run", "./tools/policystats", "-csv", str(RESULTS / "syscalls.csv"),
                    "-md", str(RESULTS / "syscalls.md")] + policies, cwd=ROOT, check=True)


def main():
    sys.stdout.reconfigure(line_buffering=True)  # show progress even when redirected
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--duration", type=int, default=10, help="seconds of HTTP load per run")
    ap.add_argument("--quick", action="store_true", help="2 reps, 3 s load: a smoke test of the harness")
    ap.add_argument("--report-only", action="store_true",
                    help="regenerate results/bench.md and syscalls.* from existing results, without measuring")
    a = ap.parse_args()
    if a.report_only:
        write_report()
        syscall_compare()
        print((RESULTS / "bench.md").read_text())
        return
    if a.quick:
        a.reps, a.duration = 2, 3
    for p in (MINIBOX, IMAGE / "usr/bin/python3", ALPINE / "bin/busybox"):
        if not p.exists():
            sys.exit(f"missing {p}: run 'make build', 'make image' and scripts/build-bench-image.sh")
    subprocess.run(["go", "build", "-o", str(LOADGEN), "./tools/loadgen"], cwd=ROOT, check=True)
    RESULTS.mkdir(exist_ok=True)
    prepare_srv()

    print("profiling workloads...")
    profile_all(a.duration)

    rows = []
    print("startup...")
    bench_timed("startup", a.reps * 6, rows, "wall_time")  # cheap, so more reps
    print("cpu-python...")
    bench_timed("cpu-python", a.reps, rows, "wall_time")
    print("syscall-dd...")
    bench_timed("syscall-dd", a.reps, rows, "wall_time")
    for w in SERVERS:
        print(f"{w}...")
        bench_http(w, a.reps, a.duration, rows)

    write_csv(rows, a.reps, a.duration)
    write_report()
    syscall_compare()
    print((RESULTS / "bench.md").read_text())
    print((RESULTS / "syscalls.md").read_text())


if __name__ == "__main__":
    main()
