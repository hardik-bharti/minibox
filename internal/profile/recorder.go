package profile

import (
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hardik-bharti/minibox/internal/security"
)

// pathKind says how a syscall uses a path argument.
type pathKind int

const (
	pathRead     pathKind = iota // looked at only
	pathWrite                    // the object itself is modified in place
	pathCreate                   // an entry is added/removed in the parent directory
	pathOpenFlag                 // open(): read or write depending on flags
)

// pathArg is one resolved path argument of a syscall.
type pathArg struct {
	path    string // absolute, as the container sees it
	kind    pathKind
	existed bool // for create-style ops: did the target exist at entry?
}

// pathSpec describes where a syscall keeps its path arguments.
type pathSpec struct {
	dirfd int // index of the dirfd argument, or -1 (relative to cwd)
	path  int // index of the path argument
	kind  pathKind
	flags int // index of open flags, or -1
}

// pathSyscalls lists the x86_64 syscalls with path arguments that matter
// for "what does the app read and write". Renames and links have two
// entries. Syscalls that operate on an fd (write, fchmod) inherit the
// classification of the open() that created the fd.
var pathSyscalls = map[string][]pathSpec{
	"open":       {{-1, 0, pathOpenFlag, 1}},
	"openat":     {{0, 1, pathOpenFlag, 2}},
	"openat2":    {{0, 1, pathOpenFlag, -2}}, // flags live in struct open_how
	"creat":      {{-1, 0, pathCreate, -1}},
	"execve":     {{-1, 0, pathRead, -1}},
	"execveat":   {{0, 1, pathRead, -1}},
	"stat":       {{-1, 0, pathRead, -1}},
	"lstat":      {{-1, 0, pathRead, -1}},
	"newfstatat": {{0, 1, pathRead, -1}},
	"statx":      {{0, 1, pathRead, -1}},
	"access":     {{-1, 0, pathRead, -1}},
	"faccessat":  {{0, 1, pathRead, -1}},
	"faccessat2": {{0, 1, pathRead, -1}},
	"readlink":   {{-1, 0, pathRead, -1}},
	"readlinkat": {{0, 1, pathRead, -1}},
	"chdir":      {{-1, 0, pathRead, -1}},
	"mkdir":      {{-1, 0, pathCreate, -1}},
	"mkdirat":    {{0, 1, pathCreate, -1}},
	"mknod":      {{-1, 0, pathCreate, -1}},
	"mknodat":    {{0, 1, pathCreate, -1}},
	"rmdir":      {{-1, 0, pathCreate, -1}},
	"unlink":     {{-1, 0, pathCreate, -1}},
	"unlinkat":   {{0, 1, pathCreate, -1}},
	"rename":     {{-1, 0, pathCreate, -1}, {-1, 1, pathCreate, -1}},
	"renameat":   {{0, 1, pathCreate, -1}, {2, 3, pathCreate, -1}},
	"renameat2":  {{0, 1, pathCreate, -1}, {2, 3, pathCreate, -1}},
	"link":       {{-1, 1, pathCreate, -1}},
	"linkat":     {{2, 3, pathCreate, -1}},
	"symlink":    {{-1, 1, pathCreate, -1}},
	"symlinkat":  {{1, 2, pathCreate, -1}},
	"chmod":      {{-1, 0, pathWrite, -1}},
	"fchmodat":   {{0, 1, pathWrite, -1}},
	"chown":      {{-1, 0, pathWrite, -1}},
	"lchown":     {{-1, 0, pathWrite, -1}},
	"fchownat":   {{0, 1, pathWrite, -1}},
	"truncate":   {{-1, 0, pathWrite, -1}},
	"utimes":     {{-1, 0, pathWrite, -1}},
	"utimensat":  {{0, 1, pathWrite, -1}},
	"setxattr":   {{-1, 0, pathWrite, -1}},
	"lsetxattr":  {{-1, 0, pathWrite, -1}},
}

// recorder turns syscall events into the observations a policy is built
// from. It implements handler.
type recorder struct {
	counts  map[string]int
	unknown map[int]int // syscall numbers missing from our table
	read    map[string]bool
	written map[string]bool // objects modified in place
	created map[string]bool // directories whose entries changed
	caps    map[string]string
	hostUID int // our UID on the host = container root
}

func newRecorder() *recorder {
	return &recorder{
		counts: map[string]int{}, unknown: map[int]int{},
		read: map[string]bool{}, written: map[string]bool{}, created: map[string]bool{},
		caps: map[string]string{}, hostUID: os.Getuid(),
	}
}

func (r *recorder) onEntry(pid, nr int, args [6]uint64) []pathArg {
	name, ok := security.SyscallName(nr)
	if !ok {
		return nil
	}
	var out []pathArg
	for _, spec := range pathSyscalls[name] {
		p, err := r.resolvePath(pid, args, spec)
		if err != nil {
			continue // e.g. a NULL path (AT_EMPTY_PATH): nothing to record
		}
		pa := pathArg{path: p, kind: spec.kind}
		if spec.kind == pathOpenFlag {
			pa.kind = r.openKind(pid, args, spec)
		}
		if pa.kind == pathCreate {
			_, err := os.Lstat(hostView(pid, p))
			pa.existed = err == nil
		}
		out = append(out, pa)
	}
	return out
}

func (r *recorder) onExit(e event) {
	name, ok := security.SyscallName(e.nr)
	if !ok {
		r.unknown[e.nr]++
		return
	}
	r.counts[name]++
	failed := e.ret < 0 && e.ret > -4096

	for _, p := range e.paths {
		if failed {
			// A failed lookup still tells us the app looked there, but
			// a failed write doesn't need write permission.
			if p.kind == pathRead {
				r.read[p.path] = true
			}
			continue
		}
		switch p.kind {
		case pathRead:
			r.read[p.path] = true
		case pathWrite:
			r.written[p.path] = true
		case pathCreate:
			// Creating, deleting or renaming changes the parent
			// directory, so that is what must be writable. (Opening an
			// existing file with O_CREAT only writes the file.)
			if p.existed && (name == "open" || name == "openat" || name == "openat2" || name == "creat") {
				r.written[p.path] = true
			} else {
				r.created[path.Dir(p.path)] = true
			}
		}
	}
	if !failed {
		r.inferCaps(name, e)
	}
}

// openKind classifies an open by its flags.
func (r *recorder) openKind(pid int, args [6]uint64, spec pathSpec) pathKind {
	var flags uint64
	if spec.flags >= 0 {
		flags = args[spec.flags]
	} else {
		// openat2(dirfd, path, struct open_how *how, size): flags is
		// the first u64 of open_how.
		var err error
		if flags, err = readUint64(pid, args[2]); err != nil {
			return pathRead
		}
	}
	switch {
	case flags&unix.O_CREAT != 0:
		return pathCreate
	case flags&(unix.O_WRONLY|unix.O_RDWR|unix.O_TRUNC|unix.O_APPEND) != 0:
		return pathWrite
	}
	return pathRead
}

// resolvePath reads a path argument and makes it absolute in the
// container's view, using the process's cwd or the dirfd. Seen from the
// host, /proc/<pid>/cwd and /proc/<pid>/fd/N already show paths relative
// to the container's root (the root is outside our mount namespace).
func (r *recorder) resolvePath(pid int, args [6]uint64, spec pathSpec) (string, error) {
	p, err := readString(pid, args[spec.path])
	if err != nil || p == "" {
		return "", fmt.Errorf("no path")
	}
	if !path.IsAbs(p) {
		base := fmt.Sprintf("/proc/%d/cwd", pid)
		if spec.dirfd >= 0 && int32(args[spec.dirfd]) != unix.AT_FDCWD {
			base = fmt.Sprintf("/proc/%d/fd/%d", pid, int32(args[spec.dirfd]))
		}
		dir, err := os.Readlink(base)
		if err != nil {
			return "", err
		}
		p = path.Join(dir, p)
	}
	return path.Clean(p), nil
}

// hostView returns a host path through which we can look at container
// path p as process pid sees it.
func hostView(pid int, p string) string { return fmt.Sprintf("/proc/%d/root%s", pid, p) }

// inferCaps records capabilities a successful syscall probably needed.
//
// ptrace sees syscalls, not the kernel's internal capable() checks (only
// eBPF on cap_capable can see those, and that needs root). So we infer
// from the syscall and its arguments, using the rules in capabilities(7).
// Each inferred capability is saved with the reason, so a human can check
// it. The list errs on the side of including a capability.
func (r *recorder) inferCaps(name string, e event) {
	add := func(c, why string) {
		if _, ok := r.caps[c]; !ok {
			r.caps[c] = why
		}
	}
	switch name {
	case "chown", "fchown", "lchown", "fchownat":
		add("CAP_CHOWN", name)
	case "setuid", "setreuid", "setresuid", "setfsuid":
		add("CAP_SETUID", name)
	case "setgid", "setregid", "setresgid", "setfsgid", "setgroups":
		add("CAP_SETGID", name)
	case "chroot":
		add("CAP_SYS_CHROOT", name)
	case "mount", "umount2", "pivot_root", "sethostname", "setdomainname", "setns", "unshare":
		add("CAP_SYS_ADMIN", name)
	case "clone":
		if e.args[0]&nsFlags != 0 {
			add("CAP_SYS_ADMIN", "clone with namespace flags")
		}
	case "settimeofday", "clock_settime":
		add("CAP_SYS_TIME", name)
	case "mknod", "mknodat":
		mode := e.args[1]
		if name == "mknodat" {
			mode = e.args[2]
		}
		if t := mode & unix.S_IFMT; t == unix.S_IFCHR || t == unix.S_IFBLK {
			add("CAP_MKNOD", name+" of a device node")
		}
	case "socket":
		family, typ := e.args[0], e.args[1]&0xf // low bits = type, rest = SOCK_* flags
		if family == unix.AF_PACKET || ((family == unix.AF_INET || family == unix.AF_INET6) && typ == unix.SOCK_RAW) {
			add("CAP_NET_RAW", "raw or packet socket")
		}
	case "bind":
		if port, ok := r.bindPort(e); ok && port > 0 && port < 1024 {
			add("CAP_NET_BIND_SERVICE", fmt.Sprintf("bind to port %d", port))
		}
	case "setxattr", "lsetxattr", "fsetxattr":
		if attr, err := readString(e.pid, e.args[1]); err == nil && attr == "security.capability" {
			add("CAP_SETFCAP", "set file capabilities")
		}
	case "kill", "tkill", "tgkill":
		// Every process in the container runs as the same UID, so
		// signalling never needs CAP_KILL.
	}
	// Changing metadata of a file we don't own needs CAP_FOWNER; writing
	// to one that isn't world-writable needs CAP_DAC_OVERRIDE. In a
	// single-UID container this only happens for files owned by unmapped
	// UIDs (shown as "nobody"), such as the host device nodes in /dev.
	for _, p := range e.paths {
		if p.kind != pathWrite {
			continue
		}
		owned, worldWritable := r.access(e.pid, p.path)
		switch {
		case owned:
		case name == "chmod" || name == "fchmodat" || name == "utimes" || name == "utimensat" ||
			name == "chown" || name == "lchown" || name == "fchownat":
			add("CAP_FOWNER", name+" on a file not owned by container root: "+p.path)
		case !worldWritable:
			add("CAP_DAC_OVERRIDE", "write to a file not owned by container root: "+p.path)
		}
	}
}

// nsFlags are the clone flags that create namespaces.
const nsFlags = unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC | unix.CLONE_NEWUSER |
	unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP

// bindPort reads the port from bind(fd, struct sockaddr *, len) for
// AF_INET/AF_INET6, where it is the big-endian u16 after the family.
func (r *recorder) bindPort(e event) (int, bool) {
	b, err := readBytes(e.pid, e.args[1], 4)
	if err != nil || len(b) < 4 {
		return 0, false
	}
	family := binary.LittleEndian.Uint16(b[0:2])
	if family != unix.AF_INET && family != unix.AF_INET6 {
		return 0, false
	}
	return int(binary.BigEndian.Uint16(b[2:4])), true
}

// access reports whether container root owns path p and whether p is
// writable by everyone (mode o+w), as seen by process pid.
func (r *recorder) access(pid int, p string) (owned, worldWritable bool) {
	fi, err := os.Stat(hostView(pid, p))
	if err != nil {
		return true, false // gone already; can't tell, assume the common case
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || int(st.Uid) == r.hostUID, fi.Mode().Perm()&0o002 != 0
}

// ignoredWritePrefixes are separate mounts that policy mode doesn't make
// read-only (/dev is a private tmpfs; /proc and /sys get the baseline's
// masking instead), so writes there don't belong in writable_paths.
var ignoredWritePrefixes = []string{"/dev", "/proc", "/sys"}

func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}
