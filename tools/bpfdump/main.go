// Command bpfdump compiles a seccomp filter the way `minibox run` would and
// writes it as JSON: every BPF instruction in readable form, plus the
// exact path a few example syscalls take through it.
//
// It produces the data behind the seccomp walkthrough in the explainer
// (docs/explainer.html), so the instructions shown there are the real
// output of our compiler, not a hand-drawn approximation.
//
// Usage:
//
//	bpfdump -policy results/policies/startup.json -trace getpid,write,mount
//	bpfdump -baseline -trace read,ptrace
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/hardik-bharti/minibox/internal/security"
)

// output is the JSON document bpfdump writes.
type output struct {
	Source       string            `json:"source"` // policy path or "docker-default"
	Syscalls     []string          `json:"allowed_syscalls"`
	Instructions []security.Insn   `json:"instructions"`
	Traces       []trace           `json:"traces"`
	Generated    string            `json:"generated_by"`
	Notes        map[string]string `json:"notes"`
}

// trace is one example syscall's path through the filter.
type trace struct {
	Syscall string   `json:"syscall"`
	Nr      int      `json:"nr"`
	Args    []uint64 `json:"args,omitempty"`
	Label   string   `json:"label"`
	Path    []int    `json:"path"` // program counters visited, in order
	Result  string   `json:"result"`
}

func main() {
	policy := flag.String("policy", "", "policy file from `minibox profile`")
	baseline := flag.Bool("baseline", false, "use the Docker default profile (baseline) instead")
	traces := flag.String("trace", "getpid,write,mount", "comma-separated syscalls to trace; clone is traced twice (fork and new user namespace)")
	out := flag.String("o", "", "write here instead of stdout")
	flag.Parse()

	cfg, source, err := config(*policy, *baseline)
	if err != nil {
		fail(err)
	}
	f, err := cfg.SeccompFilter()
	if err != nil {
		fail(err)
	}
	prog, err := f.Compile()
	if err != nil {
		fail(err)
	}

	doc := output{
		Source:       source,
		Syscalls:     f.Syscalls(),
		Instructions: security.Disassemble(prog),
		Generated:    "go run ./tools/bpfdump " + strings.Join(os.Args[1:], " "),
		Notes: map[string]string{
			"seccomp_data": "offset 0: syscall number, 4: arch, 16+8*i: argument i (each 64-bit argument is two 32-bit loads)",
		},
	}
	for _, name := range strings.Split(*traces, ",") {
		for _, c := range examples(strings.TrimSpace(name)) {
			t, err := run(prog, c)
			if err != nil {
				fail(err)
			}
			doc.Traces = append(doc.Traces, t)
		}
	}

	w := os.Stdout
	if *out != "" {
		if w, err = os.Create(*out); err != nil {
			fail(err)
		}
		defer w.Close()
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fail(err)
	}
}

func config(policy string, baseline bool) (security.Config, string, error) {
	switch {
	case baseline && policy != "":
		return security.Config{}, "", fmt.Errorf("-policy and -baseline are mutually exclusive")
	case baseline:
		return security.NewBaseline(), "docker-default", nil
	case policy == "":
		return security.Config{}, "", fmt.Errorf("give -policy FILE or -baseline")
	}
	p, err := security.LoadPolicy(policy)
	if err != nil {
		return security.Config{}, "", err
	}
	return security.NewFromPolicy(p), policy, nil
}

// examples expands a syscall name into the calls to trace. clone is the
// interesting one: the same syscall is allowed or denied by its flags.
func examples(name string) []trace {
	if name == "clone" {
		return []trace{
			{Syscall: name, Args: []uint64{uint64(unix.SIGCHLD)}, Label: "clone(SIGCHLD): an ordinary fork"},
			{Syscall: name, Args: []uint64{unix.CLONE_NEWUSER}, Label: "clone(CLONE_NEWUSER): a new user namespace"},
		}
	}
	return []trace{{Syscall: name, Label: name + "()"}}
}

func run(prog []unix.SockFilter, t trace) (trace, error) {
	nr, ok := security.SyscallNumber(t.Syscall)
	if !ok {
		return t, fmt.Errorf("unknown syscall %q", t.Syscall)
	}
	var args [6]uint64
	copy(args[:], t.Args)
	ret, path, err := security.Evaluate(prog, nr, args)
	if err != nil {
		return t, fmt.Errorf("%s: %w", t.Syscall, err)
	}
	t.Nr, t.Path, t.Result = nr, path, security.RetName(ret)
	return t, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "bpfdump:", err)
	os.Exit(1)
}
