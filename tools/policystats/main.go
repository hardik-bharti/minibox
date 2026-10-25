// Command policystats compares the size of seccomp allowlists: Docker's
// default profile (as minibox's baseline applies it on x86_64 with the
// default capabilities) versus generated minibox policies.
//
// Counts are of syscalls the compiled filter allows (in any form, e.g.
// clone only without namespace flags counts as allowed), for both sides.
//
// Usage: policystats -csv out.csv -md out.md policy.json...
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/hardik-bharti/minibox/internal/security"
)

func main() {
	csvPath := flag.String("csv", "", "write CSV here")
	mdPath := flag.String("md", "", "write Markdown here")
	flag.Parse()

	docker, err := security.DockerFilter(security.DefaultCaps)
	if err != nil {
		fail(err)
	}
	dockerSet := docker.Syscalls()

	header := []string{"profile", "syscalls", "pct_of_docker", "not_in_docker", "capabilities", "writable_paths"}
	rows := [][]string{{"docker-default (baseline)", strconv.Itoa(len(dockerSet)), "100.0", "", strconv.Itoa(len(security.DefaultCaps)), "all (rw root)"}}
	for _, path := range flag.Args() {
		p, err := security.LoadPolicy(path)
		if err != nil {
			fail(err)
		}
		// Count what is actually enforced: the policy's syscalls plus the
		// always-allowed ones, as the compiled filter allows them (the
		// same way Docker's filter is counted).
		cfg := security.NewFromPolicy(p)
		f, err := cfg.SeccompFilter()
		if err != nil {
			fail(err)
		}
		allowed := f.Syscalls()
		var extra []string
		for _, s := range allowed {
			if !slices.Contains(dockerSet, s) {
				extra = append(extra, s)
			}
		}
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		rows = append(rows, []string{
			name, strconv.Itoa(len(allowed)),
			fmt.Sprintf("%.1f", 100*float64(len(allowed))/float64(len(dockerSet))),
			strings.Join(extra, " "),
			strconv.Itoa(len(p.Capabilities)), strings.Join(p.WritablePaths, " "),
		})
	}

	if *csvPath != "" {
		f, err := os.Create(*csvPath)
		if err != nil {
			fail(err)
		}
		w := csv.NewWriter(f)
		w.Write(header)
		w.WriteAll(rows)
		f.Close()
	}
	var md strings.Builder
	md.WriteString("| Profile | Allowed syscalls | % of Docker's | Allowed but not in Docker's | Capabilities | Writable paths |\n|---|---|---|---|---|---|\n")
	for _, r := range rows {
		extra := r[3]
		if extra == "" {
			extra = "-"
		}
		fmt.Fprintf(&md, "| %s | %s | %s%% | %s | %s | %s |\n", r[0], r[1], r[2], extra, r[4], orDash(r[5]))
	}
	if *mdPath != "" {
		if err := os.WriteFile(*mdPath, []byte(md.String()), 0o644); err != nil {
			fail(err)
		}
	} else {
		fmt.Print(md.String())
	}
}

func orDash(s string) string {
	if s == "" {
		return "none (read-only root)"
	}
	return s
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "policystats:", err)
	os.Exit(1)
}
