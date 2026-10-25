#!/usr/bin/env python3
"""Run the attack suite under three hardening configurations.

Usage: tests/attacks/run.py          (from anywhere; needs bin/minibox and images/bench)

For every attack in tests/attacks/probe and every configuration:

  none      --security none                  namespaces only, no limits
  baseline  (defaults) --pids 64 --memory 256m   Phase 4 + resource limits
  policy    --policy <generated> --pids 64 --memory 256m   Phase 5 + limits

it runs `probe <attack>` in a fresh container and records BLOCKED/ALLOWED.
The policy is generated first by profiling `probe benign` (three runs,
merged), i.e. a policy for a normal small service, then used unchanged for
every attack.

Writes results/attacks.csv, results/attacks.md and
results/policies/attack-probe.json. Every number in those files comes from
this script.
"""

import csv
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MINIBOX = ROOT / "bin" / "minibox"
IMAGE = ROOT / "images" / "bench"
PROBE_DIR = ROOT / "tests" / "attacks" / "bin"
RESULTS = ROOT / "results"
POLICY = RESULTS / "policies" / "attack-probe.json"
VOLUME = ["-v", f"{PROBE_DIR}:/probe:ro"]
LIMITS = ["--pids", "64", "--memory", "256m"]

CONFIGS = {
    "none": ["--security", "none"],
    "baseline": LIMITS,
    "policy": ["--policy", str(POLICY)] + LIMITS,
}

# attack name -> what it tries (shown in the results table)
ATTACKS = {
    "mount": "mount a filesystem (tmpfs on /mnt)",
    "unshare": "create a user namespace to regain all capabilities",
    "kernel-module": "load a kernel module (init_module)",
    "ptrace": "ptrace-attach to a sibling process",
    "sysrq": "open /proc/sysrq-trigger for writing",
    "proc-sys": "write /proc/sys/net/ipv4/ip_forward",
    "kernel-info": "read host kernel info (/proc/interrupts)",
    "fork-bomb": "hold 500 processes (bounded fork bomb)",
    "memory": "allocate and touch 1 GiB",
    "raw-socket": "open a raw socket (SOCK_RAW)",
    "hostname": "change the hostname (sethostname)",
    "clock": "set the system clock (clock_settime)",
    "keyring": "add a key to the kernel keyring",
    "bpf": "use bpf() (BPF_MAP_CREATE)",
    "mknod": "create a block device node for the host disk",
    "chroot-escape": "classic chroot + '..' escape to the host fs",
    "other-container": "read another container's files",
}


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def build_probe():
    env = dict(os.environ, CGO_ENABLED="0")
    PROBE_DIR.mkdir(parents=True, exist_ok=True)
    r = run(["go", "build", "-o", str(PROBE_DIR / "probe"), "./tests/attacks/probe"], cwd=ROOT, env=env)
    if r.returncode != 0:
        sys.exit(f"building probe failed:\n{r.stderr}")
    names = run([str(PROBE_DIR / "probe"), "list"]).stdout.split()
    if sorted(names) != sorted(ATTACKS):
        sys.exit(f"attack list mismatch: probe has {names}")


def generate_policy():
    POLICY.parent.mkdir(parents=True, exist_ok=True)
    POLICY.unlink(missing_ok=True)
    for _ in range(3):
        r = run([str(MINIBOX), "profile", "--merge", "-o", str(POLICY)] + VOLUME +
                [str(IMAGE), "/probe/probe", "benign"])
        if r.returncode != 0:
            sys.exit(f"profiling failed:\n{r.stdout}{r.stderr}")
    pol = json.loads(POLICY.read_text())
    print(f"policy: {len(pol['syscalls'])} syscalls, caps {pol['capabilities']}, "
          f"writable {pol['writable_paths']}")


class OtherContainer:
    """A second container holding a secret, for the other-container attack."""

    def __init__(self, state_root):
        self.token = secrets.token_hex(8)
        self.state_root = state_root
        env = dict(os.environ, MINIBOX_ROOT=str(state_root))
        self.proc = subprocess.Popen(
            [str(MINIBOX), "run", "--security", "none", str(IMAGE),
             "sh", "-c", f"echo {self.token} > /secret; sleep 120"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.state_dir = None
        for _ in range(100):
            dirs = list(Path(state_root).iterdir())
            if dirs and (dirs[0] / "upper" / "secret").exists():
                self.state_dir = dirs[0]
                break
            time.sleep(0.05)
        if self.state_dir is None:
            self.stop()
            sys.exit("other container did not start")

    def stop(self):
        self.proc.terminate()  # minibox forwards it; second signal = kill
        time.sleep(0.2)
        self.proc.kill()
        self.proc.wait()


def attack_args(name, other):
    if name == "chroot-escape":
        return [str(Path.home())]  # exists on the host, not in the container
    if name == "other-container":
        return [other.token, str(other.state_dir)]
    return []


def run_attack(config, name, other):
    cmd = [str(MINIBOX), "run"] + CONFIGS[config] + VOLUME + \
        [str(IMAGE), "/probe/probe", name] + attack_args(name, other)
    try:
        r = run(cmd, timeout=120)
    except subprocess.TimeoutExpired:
        return "ERROR", None, "timed out"
    line = next((l for l in r.stdout.splitlines() if l.startswith(("BLOCKED", "ALLOWED"))), "")
    note = " ".join(l.removeprefix("minibox: ") for l in r.stderr.splitlines() if l.startswith("minibox:"))
    if r.returncode == 137:  # SIGKILL: the cgroup OOM killer stopped it
        return "BLOCKED", 137, ("killed: " + note) if note else "killed (SIGKILL)"
    if line:
        status, detail = line.split(" ", 1)
        if note:
            detail += f" [{note}]"
        return status, r.returncode, detail
    return "ERROR", r.returncode, (r.stdout + r.stderr).strip()[:200]


def main():
    sys.stdout.reconfigure(line_buffering=True)  # show progress even when redirected
    for p in (MINIBOX, IMAGE / "usr/bin/python3"):
        if not p.exists():
            sys.exit(f"missing {p}: run 'make build' and scripts/build-bench-image.sh")
    build_probe()
    generate_policy()

    rows = []
    state_root = Path(tempfile.mkdtemp(prefix="minibox-other-"))
    other = OtherContainer(state_root)
    try:
        for name in ATTACKS:
            for config in CONFIGS:
                status, code, detail = run_attack(config, name, other)
                rows.append(dict(attack=name, description=ATTACKS[name], config=config,
                                 result=status, exit_code=code, detail=detail))
                print(f"{name:16} {config:9} {status:8} {detail[:90]}")
    finally:
        other.stop()
        shutil.rmtree(state_root, ignore_errors=True)

    write_csv(rows)
    write_markdown(rows)
    print(f"wrote {RESULTS / 'attacks.csv'} and {RESULTS / 'attacks.md'}")


def write_csv(rows):
    with open(RESULTS / "attacks.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def write_markdown(rows):
    by = {(r["attack"], r["config"]): r for r in rows}
    out = ["# Attack suite results", "",
           "Generated by `tests/attacks/run.py`. Do not edit by hand.", "",
           "Configurations: **none** = `--security none`, no limits; "
           "**baseline** = Phase 4 defaults + `--pids 64 --memory 256m`; "
           "**policy** = `--policy results/policies/attack-probe.json` "
           "(profiled from `probe benign`) + the same limits.", "",
           "| # | Attack | none | baseline | policy |", "|---|---|---|---|---|"]
    for i, name in enumerate(ATTACKS, 1):
        cells = [by[(name, c)]["result"] for c in CONFIGS]
        out.append(f"| {i} | {ATTACKS[name]} (`{name}`) | " + " | ".join(cells) + " |")
    out += ["", "| Config | Blocked | Allowed | Error |", "|---|---|---|---|"]
    for c in CONFIGS:
        res = [by[(n, c)]["result"] for n in ATTACKS]
        out.append(f"| {c} | {res.count('BLOCKED')}/{len(res)} | {res.count('ALLOWED')} | {res.count('ERROR')} |")
    out += ["", "## Details (what the probe reported)", "",
            "| Attack | Config | Result | Detail |", "|---|---|---|---|"]
    for r in rows:
        detail = r["detail"].replace("|", "\\|")
        out.append(f"| `{r['attack']}` | {r['config']} | {r['result']} | {detail} |")
    (RESULTS / "attacks.md").write_text("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
