package security

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// Insn is one BPF instruction of a compiled filter, with a readable form.
// `minibox ui` and tools/bpfdump use it to show what the kernel really
// runs on every syscall.
type Insn struct {
	PC      int    `json:"pc"`
	Code    uint16 `json:"code"`
	Jt      uint8  `json:"jt"`
	Jf      uint8  `json:"jf"`
	K       uint32 `json:"k"`
	Asm     string `json:"asm"`     // classic bpf_asm syntax, e.g. "jeq #39, 1, 0"
	Explain string `json:"explain"` // the same in words, with syscall names
}

// Disassemble turns a program from Compile into readable instructions.
//
// Compile's programs are simple: every comparison is preceded, in program
// order, by the load it compares. So remembering the last loaded field is
// enough to say "syscall number == 39 (getpid)" instead of "A == 39".
func Disassemble(prog []unix.SockFilter) []Insn {
	out := make([]Insn, len(prog))
	field := ""
	for pc, in := range prog {
		i := Insn{PC: pc, Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			field = fieldName(in.K)
			i.Asm = fmt.Sprintf("ld [%d]", in.K)
			i.Explain = "load " + field
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			i.Asm = fmt.Sprintf("and #%#x", in.K)
			i.Explain = fmt.Sprintf("keep only the bits in %#x", in.K)
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			op, sym := "jeq", "=="
			if in.Code&0xf0 == unix.BPF_JGE {
				op, sym = "jge", ">="
			}
			i.Asm = fmt.Sprintf("%s #%#x, %d, %d", op, in.K, in.Jt, in.Jf)
			i.Explain = fmt.Sprintf("if %s %s %s: go to %d, else %d",
				field, sym, valueName(field, in.K), pc+1+int(in.Jt), pc+1+int(in.Jf))
		case unix.BPF_RET | unix.BPF_K:
			i.Asm = fmt.Sprintf("ret #%#x", in.K)
			i.Explain = "return " + RetName(in.K)
		default:
			i.Asm = fmt.Sprintf("code %#x k %#x", in.Code, in.K)
			i.Explain = "(instruction minibox does not emit)"
		}
		out[pc] = i
	}
	return out
}

// fieldName names a struct seccomp_data offset (see the layout in seccomp.go).
func fieldName(off uint32) string {
	switch {
	case off == offNr:
		return "syscall number"
	case off == offArch:
		return "arch"
	case off >= offArgs && off < offArgs+48:
		half := "low"
		if (off-offArgs)%8 == 4 {
			half = "high"
		}
		return fmt.Sprintf("arg%d (%s 32 bits)", (off-offArgs)/8, half)
	}
	return fmt.Sprintf("offset %d", off)
}

// valueName shows a compared constant in the most useful form.
func valueName(field string, k uint32) string {
	switch field {
	case "syscall number":
		if name, ok := SyscallName(int(k)); ok {
			return fmt.Sprintf("%d (%s)", k, name)
		}
		if k == x32SyscallBit {
			return fmt.Sprintf("%#x (x32 ABI bit)", k)
		}
	case "arch":
		if k == unix.AUDIT_ARCH_X86_64 {
			return fmt.Sprintf("%#x (x86_64)", k)
		}
	}
	return fmt.Sprintf("%#x", k)
}

// RetName names a seccomp return value, e.g. "ERRNO(EPERM)".
func RetName(k uint32) string {
	switch k & unix.SECCOMP_RET_ACTION_FULL {
	case unix.SECCOMP_RET_ALLOW:
		return "ALLOW"
	case unix.SECCOMP_RET_KILL_PROCESS:
		return "KILL_PROCESS"
	case unix.SECCOMP_RET_ERRNO:
		errno := unix.Errno(k & unix.SECCOMP_RET_DATA)
		return fmt.Sprintf("ERRNO(%s)", unix.ErrnoName(errno))
	}
	return fmt.Sprintf("%#x", k)
}

// Evaluate runs prog on an x86_64 syscall the way the kernel would and
// returns the action plus every instruction visited, in order. It lets the
// UI animate one syscall's path through the filter, and gives the tests a
// second interpreter to cross-check.
func Evaluate(prog []unix.SockFilter, nr int, args [6]uint64) (ret uint32, path []int, err error) {
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[offNr:], uint32(nr))
	binary.LittleEndian.PutUint32(data[offArch:], unix.AUDIT_ARCH_X86_64)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[offArgs+8*i:], a)
	}
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		path = append(path, pc)
		in := prog[pc]
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if int(in.K)+4 > len(data) {
				return 0, path, fmt.Errorf("pc %d: load beyond seccomp_data", pc)
			}
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			acc &= in.K
		case unix.BPF_RET | unix.BPF_K:
			return in.K, path, nil
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			cond := acc == in.K
			if in.Code&0xf0 == unix.BPF_JGE {
				cond = acc >= in.K
			}
			if cond {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		default:
			return 0, path, fmt.Errorf("pc %d: unsupported instruction %#x", pc, in.Code)
		}
	}
	return 0, path, fmt.Errorf("program ran off the end without returning")
}

// SyscallNumber is the x86_64 number of a syscall name.
func SyscallNumber(name string) (int, bool) {
	nr, ok := syscallNumbers[name]
	return nr, ok
}
