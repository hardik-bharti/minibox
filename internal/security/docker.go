package security

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"

	"golang.org/x/sys/unix"
)

// dockerProfileJSON is Docker's default seccomp profile, unmodified (see
// profiles/NOTICE). Embedding it means our baseline *is* Docker's policy,
// interpreted by our own compiler, rather than a hand-copied list that
// could drift.
//
//go:embed profiles/docker-default.json
var dockerProfileJSON []byte

// dockerProfile mirrors the parts of Docker's JSON format we use.
type dockerProfile struct {
	DefaultErrnoRet int `json:"defaultErrnoRet"`
	Syscalls        []struct {
		Names    []string `json:"names"`
		Action   string   `json:"action"`
		ErrnoRet int      `json:"errnoRet"`
		Args     []struct {
			Index    int    `json:"index"`
			Value    uint64 `json:"value"`
			ValueTwo uint64 `json:"valueTwo"`
			Op       string `json:"op"`
		} `json:"args"`
		Includes dockerCond `json:"includes"`
		Excludes dockerCond `json:"excludes"`
	} `json:"syscalls"`
}

type dockerCond struct {
	Caps      []string `json:"caps"`
	Arches    []string `json:"arches"`
	MinKernel string   `json:"minKernel"`
}

// Docker's architecture names for our platform.
var ourArches = []string{"amd64", "x86_64"}

// DockerFilter builds the seccomp filter Docker would apply on x86_64 to a
// container holding capabilities caps. Entries are conditional: e.g.
// mount/unshare/setns are only allowed with CAP_SYS_ADMIN, clone only
// without namespace flags. We support the conditions Docker's default
// profile uses on x86_64: caps, arches and minKernel (every entry needs
// <= 4.8; we require >= 5.11 anyway, see scripts/check-env.sh).
//
// Names that don't exist on x86_64 (other architectures' syscalls) are
// skipped, which matches libseccomp's behaviour.
func DockerFilter(caps []string) (*Filter, error) {
	var p dockerProfile
	if err := json.Unmarshal(dockerProfileJSON, &p); err != nil {
		return nil, fmt.Errorf("parse Docker profile: %w", err)
	}
	f := &Filter{Default: Action{Errno: unix.Errno(p.DefaultErrnoRet)}}

	for _, e := range p.Syscalls {
		if !condHolds(e.Includes, caps, true) || condHolds(e.Excludes, caps, false) {
			continue
		}
		act := ActAllow
		switch e.Action {
		case "SCMP_ACT_ALLOW":
		case "SCMP_ACT_ERRNO":
			act = Action{Errno: unix.Errno(e.ErrnoRet)}
		default:
			return nil, fmt.Errorf("unsupported Docker action %q", e.Action)
		}
		var args []ArgCmp
		for _, a := range e.Args {
			op, ok := map[string]CmpOp{
				"SCMP_CMP_EQ": OpEQ, "SCMP_CMP_NE": OpNE,
				"SCMP_CMP_LT": OpLT, "SCMP_CMP_MASKED_EQ": OpMaskedEQ,
			}[a.Op]
			if !ok {
				return nil, fmt.Errorf("unsupported Docker comparison %q", a.Op)
			}
			args = append(args, ArgCmp{Index: a.Index, Op: op, Value: a.Value, ValueTwo: a.ValueTwo})
		}
		for _, name := range e.Names {
			if _, ok := syscallNumbers[name]; ok {
				f.Rules = append(f.Rules, Rule{Name: name, Action: act, Args: args})
			}
		}
	}
	return f, nil
}

// condHolds reports whether an includes/excludes block applies. For
// includes every listed field must match (an empty block always matches);
// for excludes any matching field excludes the entry (an empty block never
// does).
func condHolds(c dockerCond, caps []string, isInclude bool) bool {
	archMatch := slices.ContainsFunc(c.Arches, func(a string) bool { return slices.Contains(ourArches, a) })
	if isInclude {
		for _, need := range c.Caps {
			if !slices.Contains(caps, need) {
				return false
			}
		}
		return len(c.Arches) == 0 || archMatch
	}
	for _, cp := range c.Caps {
		if slices.Contains(caps, cp) {
			return true
		}
	}
	return archMatch
}
