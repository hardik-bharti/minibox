package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PolicyVersion is bumped if the file format changes incompatibly.
const PolicyVersion = 1

// PolicyFile is the JSON written by `minibox profile` and read by
// `minibox run --policy`. The first three fields are enforced; Observed
// is information for humans (and the evaluation scripts) only.
type PolicyFile struct {
	Version       int       `json:"minibox_policy"`
	Generated     time.Time `json:"generated"`
	Command       []string  `json:"command"`
	Syscalls      []string  `json:"syscalls"`
	Capabilities  []string  `json:"capabilities"`
	WritablePaths []string  `json:"writable_paths"`
	Observed      Observed  `json:"observed"`
}

// Observed records what the profiler saw.
type Observed struct {
	SyscallCounts map[string]int    `json:"syscall_counts"`
	CapReasons    map[string]string `json:"capability_reasons,omitempty"`
	ReadPaths     []string          `json:"read_paths"`
	WrittenPaths  []string          `json:"written_paths"`
}

// LoadPolicy reads and validates a policy file.
func LoadPolicy(path string) (*PolicyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p PolicyFile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return &p, nil
}

// Validate checks that the policy is something we can enforce.
func (p *PolicyFile) Validate() error {
	if p.Version != PolicyVersion {
		return fmt.Errorf("unsupported minibox_policy version %d (want %d)", p.Version, PolicyVersion)
	}
	if len(p.Syscalls) == 0 {
		return fmt.Errorf("empty syscall list")
	}
	for _, s := range p.Syscalls {
		if _, ok := syscallNumbers[s]; !ok {
			return fmt.Errorf("unknown syscall %q", s)
		}
	}
	if err := ValidateCaps(p.Capabilities); err != nil {
		return err
	}
	for _, w := range p.WritablePaths {
		if !filepath.IsAbs(w) || filepath.Clean(w) != w {
			return fmt.Errorf("writable path %q must be absolute and clean", w)
		}
	}
	return nil
}

// Save writes the policy as indented JSON.
func (p *PolicyFile) Save(path string) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// SyscallName returns the name of an x86_64 syscall number, for the tracer.
func SyscallName(nr int) (string, bool) {
	name, ok := syscallNames()[nr]
	return name, ok
}

var nameByNr map[int]string

func syscallNames() map[int]string {
	if nameByNr == nil {
		nameByNr = make(map[int]string, len(syscallNumbers))
		for n, nr := range syscallNumbers {
			nameByNr[nr] = n
		}
	}
	return nameByNr
}
