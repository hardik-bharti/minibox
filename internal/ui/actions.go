package ui

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardik-bharti/minibox/internal/security"
)

// Action is one demo the page can start. Every parameter must be one of
// its Choices, so the page can only pick from what is listed here.
type Action struct {
	ID     string  `json:"id"`
	Panel  string  `json:"panel"`
	Title  string  `json:"title"`
	Params []Param `json:"params,omitempty"`
	run    func(j *job, p map[string]string) error
}

// Param is one choice the page offers for an action.
type Param struct {
	Name    string   `json:"name"`
	Label   string   `json:"label"`
	Choices []Choice `json:"choices"`
	Default string   `json:"default"`
}

// Choice is one allowed value of a Param.
type Choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// validate checks every parameter against the action's choices and fills
// in defaults. Unknown parameters are rejected.
func (a *Action) validate(in map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range a.Params {
		v, ok := in[p.Name]
		if !ok || v == "" {
			v = p.Default
		}
		if !p.allows(v) {
			return nil, fmt.Errorf("%s: %q is not one of the offered choices", p.Name, v)
		}
		out[p.Name] = v
	}
	for k := range in {
		if _, ok := out[k]; !ok {
			return nil, fmt.Errorf("unknown parameter %q", k)
		}
	}
	return out, nil
}

func (p Param) allows(v string) bool {
	for _, c := range p.Choices {
		if c.Value == v {
			return true
		}
	}
	return false
}

func choices(values ...string) []Choice {
	out := make([]Choice, len(values))
	for i, v := range values {
		out[i] = Choice{Value: v, Label: v}
	}
	return out
}

// workload is a small program the profile panel can trace and enforce.
type workload struct {
	ID, Title string
	Bench     bool // needs images/bench (python3)
	Probe     bool // needs the attack probe mounted at /probe
	Argv      []string
}

var workloads = []workload{
	{ID: "note", Title: "Write a note to /tmp", Argv: []string{"sh", "-c", "echo hello > /tmp/note && cat /tmp/note"}},
	{ID: "list", Title: "List /etc", Argv: []string{"ls", "-l", "/etc"}},
	{ID: "checksum", Title: "Checksum a file", Argv: []string{"sha256sum", "/etc/os-release"}},
	{ID: "benign", Title: "The attack suite's benign service", Probe: true, Argv: []string{"/probe/probe", "benign"}},
	{ID: "python", Title: "Python computation", Bench: true, Argv: []string{"python3", "-c", "print(sum(i * i for i in range(200000)))"}},
}

// attacks mirrors tests/attacks/run.py (same names, same descriptions).
var attacks = []struct{ Name, What string }{
	{"mount", "mount a filesystem (tmpfs on /mnt)"},
	{"unshare", "create a user namespace to regain all capabilities"},
	{"kernel-module", "load a kernel module (init_module)"},
	{"ptrace", "ptrace-attach to a sibling process"},
	{"sysrq", "open /proc/sysrq-trigger for writing"},
	{"proc-sys", "write /proc/sys/net/ipv4/ip_forward"},
	{"kernel-info", "read host kernel info (/proc/interrupts)"},
	{"fork-bomb", "hold 500 processes (bounded fork bomb)"},
	{"memory", "allocate and touch 1 GiB"},
	{"raw-socket", "open a raw socket (SOCK_RAW)"},
	{"hostname", "change the hostname (sethostname)"},
	{"clock", "set the system clock (clock_settime)"},
	{"keyring", "add a key to the kernel keyring"},
	{"bpf", "use bpf() (BPF_MAP_CREATE)"},
	{"mknod", "create a block device node for the host disk"},
	{"chroot-escape", "classic chroot + '..' escape to the host fs"},
	{"other-container", "read another container's files"},
}

// attackConfigs are the three configurations of the evaluation, with the
// same flags as tests/attacks/run.py. The policy path is filled in later.
var attackConfigs = []string{"none", "baseline", "policy"}

var attackLimits = []string{"--pids", "64", "--memory", "256m"}

// catalogue builds the list of actions for this server.
func (s *Server) catalogue() []*Action {
	var wl []Choice
	for _, w := range s.workloads() {
		wl = append(wl, Choice{Value: w.ID, Label: w.Title})
	}
	var at []Choice
	for _, a := range attacks {
		at = append(at, Choice{Value: a.Name, Label: a.What})
	}
	return []*Action{
		{ID: "isolation", Panel: "isolation", Title: "Compare host and container",
			Params: []Param{{Name: "hostname", Label: "Container hostname", Choices: choices("demo", "viva", "box1"), Default: "demo"}},
			run:    s.runIsolation},
		{ID: "overlay", Panel: "isolation", Title: "Change a file in the image", run: s.runOverlay},
		{ID: "memory", Panel: "limits", Title: "Memory hog",
			Params: []Param{{Name: "limit", Label: "--memory", Choices: choices("32m", "64m", "128m"), Default: "64m"}},
			run:    s.runMemory},
		{ID: "pids", Panel: "limits", Title: "Fork loop",
			Params: []Param{{Name: "limit", Label: "--pids", Choices: choices("10", "20", "40"), Default: "20"}},
			run:    s.runPids},
		{ID: "cpu", Panel: "limits", Title: "CPU burner",
			Params: []Param{{Name: "limit", Label: "--cpus", Choices: choices("0.25", "0.5", "1"), Default: "0.5"}},
			run:    s.runCPU},
		{ID: "profile", Panel: "profile", Title: "Profile a program",
			Params: []Param{{Name: "workload", Label: "Program", Choices: wl, Default: "note"}},
			run:    s.runProfile},
		{ID: "enforce", Panel: "profile", Title: "Run under a policy",
			Params: []Param{
				{Name: "policy", Label: "Policy from", Choices: wl, Default: "note"},
				{Name: "workload", Label: "Program to run", Choices: wl, Default: "note"},
			},
			run: s.runEnforce},
		{ID: "attack", Panel: "attacks", Title: "Run one attack",
			Params: []Param{{Name: "attack", Label: "Attack", Choices: at, Default: "mount"}},
			run:    s.runAttack},
		{ID: "attack-all", Panel: "attacks", Title: "Run all 17 attacks", run: s.runAllAttacks},
	}
}

// workloads lists the programs whose images and helpers are present.
func (s *Server) workloads() []workload {
	var out []workload
	for _, w := range workloads {
		if (w.Bench && !s.have.bench) || (w.Probe && !s.have.probe) {
			continue
		}
		out = append(out, w)
	}
	return out
}

func findWorkload(id string) workload {
	for _, w := range workloads {
		if w.ID == id {
			return w
		}
	}
	panic("unknown workload " + id) // validate() only lets listed IDs through
}

// imageFor picks the image a workload runs in.
func (s *Server) imageFor(w workload) string {
	if w.Bench {
		return s.cfg.BenchImage
	}
	return s.cfg.Image
}

// probeVolume mounts the attack probe read-only at /probe.
func (s *Server) probeVolume() []string {
	return []string{"-v", filepath.Dir(s.cfg.Probe) + ":/probe:ro"}
}

// Phase 1: isolation.

func (s *Server) runIsolation(j *job, p map[string]string) error {
	home, _ := os.UserHomeDir()
	res, err := j.minibox(runOpts{}, "run", "--hostname", p["hostname"], s.cfg.Image,
		"sh", "-c", isolationScript(home))
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("container exited with status %d", res.Code)
	}
	j.result(map[string]any{
		"kind": "isolation", "facts": isolationFacts,
		"host": hostView(), "container": parseKV(res.Out),
	})
	return nil
}

func (s *Server) runOverlay(j *job, _ map[string]string) error {
	res, err := j.minibox(runOpts{}, "run", s.cfg.Image, "sh", "-c",
		`echo "changed inside container $(hostname)" > /etc/motd && echo "inside=$(head -n 1 /etc/motd)"`)
	if err != nil {
		return err
	}
	imageFile := filepath.Join(s.cfg.Image, "etc", "motd")
	b, err := os.ReadFile(imageFile)
	if err != nil {
		return err
	}
	first, _, _ := strings.Cut(string(b), "\n")
	j.result(map[string]any{
		"kind": "overlay", "inside": parseKV(res.Out)["inside"],
		"image": first, "image_path": imageFile, "code": res.Code,
	})
	return nil
}

// Phase 2: cgroup limits. Each runs with --stats so minibox prints the
// final accounting, and with watch so the page gets live readings.

func (s *Server) runMemory(j *job, p map[string]string) error {
	args := append([]string{"run", "--memory", p["limit"], "--stats"}, s.probeVolume()...)
	if !s.have.probe {
		return errNoProbe
	}
	res, err := j.minibox(runOpts{watch: true}, append(args, s.cfg.Image, "/probe/probe", "grow-memory")...)
	return s.limitResult(j, "memory", p["limit"], res, err)
}

func (s *Server) runPids(j *job, p map[string]string) error {
	// Starts a sleeper every 0.1 s, so the count climbs visibly to the
	// limit; past it, the shell's fork() fails with EAGAIN.
	res, err := j.minibox(runOpts{watch: true}, "run", "--pids", p["limit"], "--stats", s.cfg.Image,
		"sh", "-c", "for i in $(seq 60); do sleep 6 & sleep 0.1; done 2>&1 | head -n 5; wait")
	return s.limitResult(j, "pids", p["limit"], res, err)
}

func (s *Server) runCPU(j *job, p map[string]string) error {
	// A busy loop wants a whole CPU; cpu.max lets it run only for the
	// quota in each 100 ms period, then throttles it until the next one.
	//
	// The outer shell matters: busybox timeout execs the command itself
	// and kills it from a child. If the loop were PID 1, the kernel would
	// ignore that SIGTERM (PID 1 only gets signals it has a handler for),
	// so it would never stop.
	res, err := j.minibox(runOpts{watch: true}, "run", "--cpus", p["limit"], "--stats", s.cfg.Image,
		"sh", "-c", `timeout 6 sh -c "while :; do :; done"; true`)
	return s.limitResult(j, "cpu", p["limit"], res, err)
}

// limitResult reports minibox's final --stats line and limit messages.
func (s *Server) limitResult(j *job, kind, limit string, res cmdResult, err error) error {
	if err != nil {
		return err
	}
	stats := map[string]string{}
	for _, l := range res.Err {
		if rest, ok := strings.CutPrefix(l, "minibox stats: "); ok {
			for _, f := range strings.Fields(rest) {
				if k, v, ok := strings.Cut(f, "="); ok {
					stats[k] = v
				}
			}
		}
	}
	j.result(map[string]any{
		"kind": "limit", "limit_kind": kind, "limit": limit, "code": res.Code,
		"stats": stats, "notes": stderrNotes(res.Err),
	})
	return nil
}

var errNoProbe = fmt.Errorf("the attack probe is not built: run `make probe` and restart `minibox ui`")

// Phase 5: profile, then enforce.

func (s *Server) runProfile(j *job, p map[string]string) error {
	w := findWorkload(p["workload"])
	policy := filepath.Join(s.cfg.StateDir, "policy-"+w.ID+".json")
	events := filepath.Join(s.cfg.StateDir, fmt.Sprintf("events-%d.jsonl", j.id))
	if err := os.WriteFile(events, nil, 0o600); err != nil {
		return err
	}
	defer os.Remove(events)

	args := []string{"profile", "-o", policy, "--events", events}
	if w.Probe {
		args = append(args, s.probeVolume()...)
	}
	args = append(append(args, s.imageFor(w)), w.Argv...)
	res, err := j.minibox(runOpts{events: events}, args...)
	if err != nil {
		return err
	}
	pol, err := security.LoadPolicy(policy)
	if err != nil {
		return fmt.Errorf("profile produced no usable policy (exit %d): %w", res.Code, err)
	}
	s.setPolicy(w.ID, policy)
	summary, err := policySummary(pol)
	if err != nil {
		return err
	}
	summary["workload"], summary["title"], summary["code"] = w.ID, w.Title, res.Code
	j.result(summary)
	return nil
}

// policySummary is what the page shows about a policy. "allowed" counts
// syscalls the compiled filter lets through, the same way
// tools/policystats counts Docker's profile, so the two are comparable.
func policySummary(pol *security.PolicyFile) (map[string]any, error) {
	cfg := security.NewFromPolicy(pol)
	f, err := cfg.SeccompFilter()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"kind": "policy", "syscalls": pol.Syscalls, "allowed": f.Syscalls(),
		"capabilities": pol.Capabilities, "capability_reasons": pol.Observed.CapReasons,
		"writable_paths": pol.WritablePaths, "counts": pol.Observed.SyscallCounts,
		"read_paths": pol.Observed.ReadPaths, "written_paths": pol.Observed.WrittenPaths,
	}, nil
}

func (s *Server) runEnforce(j *job, p map[string]string) error {
	policy, ok := s.policy(p["policy"])
	if !ok {
		return fmt.Errorf("no policy for %q yet: profile it first", findWorkload(p["policy"]).Title)
	}
	w := findWorkload(p["workload"])
	args := []string{"run", "--policy", policy}
	if w.Probe {
		args = append(args, s.probeVolume()...)
	}
	res, err := j.minibox(runOpts{}, append(append(args, s.imageFor(w)), w.Argv...)...)
	if err != nil {
		return err
	}
	j.result(map[string]any{
		"kind": "enforce", "policy": p["policy"], "workload": w.ID, "title": w.Title,
		"code": res.Code, "denied": deniedLines(append(res.Out, res.Err...)),
	})
	return nil
}

// deniedLines picks out the error messages typical of a policy saying no.
func deniedLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		low := strings.ToLower(l)
		if strings.Contains(low, "operation not permitted") || strings.Contains(low, "read-only file system") ||
			strings.Contains(low, "permission denied") || strings.Contains(low, "function not implemented") {
			out = append(out, l)
		}
	}
	return out
}

// Phase 6: the attack suite, as in tests/attacks/run.py.

func (s *Server) runAttack(j *job, p map[string]string) error {
	return s.attacks(j, []string{p["attack"]})
}

func (s *Server) runAllAttacks(j *job, _ map[string]string) error {
	var names []string
	for _, a := range attacks {
		names = append(names, a.Name)
	}
	return s.attacks(j, names)
}

func (s *Server) attacks(j *job, names []string) error {
	if !s.have.probe {
		return errNoProbe
	}
	policy, err := s.attackPolicy(j)
	if err != nil {
		return err
	}
	configs := map[string][]string{
		"none":     {"--security", "none"},
		"baseline": attackLimits,
		"policy":   append([]string{"--policy", policy}, attackLimits...),
	}
	for _, name := range names {
		var other *otherContainer
		if name == "other-container" {
			if other, err = s.startOther(j); err != nil {
				return err
			}
		}
		for _, c := range attackConfigs {
			args := append(append([]string{"run"}, configs[c]...), s.probeVolume()...)
			args = append(args, s.attackImage(), "/probe/probe", name)
			args = append(args, attackArgs(name, other)...)
			res, err := j.minibox(runOpts{timeout: 120 * time.Second}, args...)
			if err != nil {
				other.stop()
				return err
			}
			status, detail := attackOutcome(res)
			j.result(map[string]any{"kind": "attack", "attack": name, "config": c,
				"result": status, "detail": detail, "code": res.Code})
		}
		other.stop()
	}
	return nil
}

// attackImage is the image the evaluation used (bench), or Alpine.
func (s *Server) attackImage() string {
	if s.have.bench {
		return s.cfg.BenchImage
	}
	return s.cfg.Image
}

// attackPolicy returns the policy the evaluation generated
// (results/policies/attack-probe.json). If `make attacks` hasn't been run,
// it is generated the same way: profile `probe benign` three times, merged.
func (s *Server) attackPolicy(j *job) (string, error) {
	if p, ok := s.attackPolicyFile(); ok {
		return p, nil
	}
	out := filepath.Join(s.cfg.StateDir, "attack-probe.json")
	for range 3 {
		args := append([]string{"profile", "--merge", "-o", out}, s.probeVolume()...)
		res, err := j.minibox(runOpts{}, append(args, s.attackImage(), "/probe/probe", "benign")...)
		if err != nil {
			return "", err
		}
		if res.Code != 0 {
			return "", fmt.Errorf("profiling probe benign failed with status %d", res.Code)
		}
	}
	s.setPolicy("attack-probe", out)
	return out, nil
}

// attackOutcome reads the probe's verdict, like run_attack in run.py.
func attackOutcome(res cmdResult) (status, detail string) {
	notes := strings.Join(stderrNotes(res.Err), " ")
	if res.Code == 137 { // SIGKILL: the cgroup OOM killer stopped it
		if notes != "" {
			return "BLOCKED", "killed: " + notes
		}
		return "BLOCKED", "killed (SIGKILL)"
	}
	for _, l := range res.Out {
		if st, d, ok := strings.Cut(l, " "); ok && (st == "BLOCKED" || st == "ALLOWED") {
			if notes != "" {
				d += " [" + notes + "]"
			}
			return st, d
		}
	}
	return "ERROR", strings.TrimSpace(strings.Join(append(res.Out, res.Err...), " "))
}

func attackArgs(name string, other *otherContainer) []string {
	switch name {
	case "chroot-escape":
		home, _ := os.UserHomeDir()
		return []string{home} // exists on the host, not in the container
	case "other-container":
		return []string{other.token, other.stateDir}
	}
	return nil
}

// otherContainer is a second container holding a secret, for the
// other-container attack (the same setup as run.py's OtherContainer).
type otherContainer struct {
	cmd      *exec.Cmd
	exited   chan struct{}
	root     string
	stateDir string
	token    string
}

func (s *Server) startOther(j *job) (*otherContainer, error) {
	b := make([]byte, 8)
	rand.Read(b)
	o := &otherContainer{token: hex.EncodeToString(b)}
	var err error
	if o.root, err = os.MkdirTemp("", "minibox-other-"); err != nil {
		return nil, err
	}
	args := []string{"run", "--security", "none", s.attackImage(), "sh", "-c", "echo " + o.token + " > /secret; sleep 120"}
	o.cmd = exec.Command(s.cfg.Exe, args...)
	o.cmd.Env = append(os.Environ(), "MINIBOX_ROOT="+o.root)
	j.send(Msg{Type: "cmd", Argv: append([]string{"MINIBOX_ROOT=" + o.root, "minibox"}, args...), Text: "helper: a second container with a secret, in the background"})
	if err := o.cmd.Start(); err != nil {
		os.RemoveAll(o.root)
		return nil, err
	}
	o.exited = make(chan struct{})
	go func() { o.cmd.Wait(); close(o.exited) }()
	for range 100 {
		dirs, _ := os.ReadDir(o.root)
		if len(dirs) == 1 {
			d := filepath.Join(o.root, dirs[0].Name())
			if _, err := os.Stat(filepath.Join(d, "upper", "secret")); err == nil {
				o.stateDir = d
				return o, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	o.stop()
	return nil, fmt.Errorf("the helper container did not start")
}

// stop ends the helper container. Safe on nil (most attacks have none).
func (o *otherContainer) stop() {
	if o == nil {
		return
	}
	stopGently(o.cmd.Process, o.exited)
	<-o.exited
	os.RemoveAll(o.root)
}
