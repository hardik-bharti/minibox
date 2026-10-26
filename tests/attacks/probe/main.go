// Command probe runs one container escape/abuse attempt and reports
// whether it was BLOCKED or ALLOWED. It is mounted read-only into the
// container at /probe by tests/attacks/run.sh.
//
// Every attack is a benign misconfiguration/policy test: it tries an
// operation a well-confined container should not be able to do, and undoes
// or avoids any real effect. Nothing here exploits a kernel bug.
//
// Exit status: 0 = BLOCKED (the confinement held), 1 = ALLOWED (the attack
// worked), 2 = ERROR (the test itself could not run).
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type result struct {
	allowed bool
	detail  string
}

func blocked(format string, a ...any) result { return result{false, fmt.Sprintf(format, a...)} }
func allowed(format string, a ...any) result { return result{true, fmt.Sprintf(format, a...)} }

// errResult turns a syscall error into BLOCKED, or nil into ALLOWED.
func errResult(op string, err error) result {
	if err != nil {
		return blocked("%s: %v", op, err)
	}
	return allowed("%s succeeded", op)
}

var attacks = map[string]func(args []string) result{
	"mount":           attackMount,
	"unshare":         attackUnshare,
	"kernel-module":   attackKernelModule,
	"ptrace":          attackPtrace,
	"sysrq":           attackSysrq,
	"proc-sys":        attackProcSys,
	"kernel-info":     attackKernelInfo,
	"fork-bomb":       attackForkBomb,
	"memory":          attackMemory,
	"raw-socket":      attackRawSocket,
	"hostname":        attackHostname,
	"clock":           attackClock,
	"keyring":         attackKeyring,
	"bpf":             attackBPF,
	"mknod":           attackMknod,
	"chroot-escape":   attackChrootEscape,
	"other-container": attackOtherContainer,
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "benign":
		os.Exit(benign())
	case "sleep": // helper for ptrace
		time.Sleep(10 * time.Second)
		return
	case "ptrace-attach": // helper for ptrace
		os.Exit(ptraceAttach(os.Args[2]))
	case "grow-memory": // demo workload for `minibox ui`
		growMemory()
		return
	case "list":
		names := make([]string, 0, len(attacks))
		for n := range attacks {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Println(strings.Join(names, "\n"))
		return
	}
	fn, ok := attacks[os.Args[1]]
	if !ok {
		usage()
	}
	r := fn(os.Args[2:])
	if r.allowed {
		fmt.Printf("ALLOWED %s\n", r.detail)
		os.Exit(1)
	}
	fmt.Printf("BLOCKED %s\n", r.detail)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: probe <attack>|benign|grow-memory|list")
	os.Exit(2)
}

// benign is the workload profiled to generate the "policy" configuration:
// what a normal small service does (read config, write a temp file, spawn
// a helper process, allocate memory, use a socket) and nothing more.
func benign() int {
	if _, err := os.ReadFile("/etc/os-release"); err != nil {
		fmt.Println("read:", err)
		return 2
	}
	if err := os.WriteFile("/tmp/probe-benign", []byte("ok\n"), 0o644); err != nil {
		fmt.Println("write:", err)
		return 2
	}
	os.Remove("/tmp/probe-benign")
	if err := exec.Command("/bin/true").Run(); err != nil {
		fmt.Println("spawn:", err)
		return 2
	}
	buf := make([]byte, 16<<20)
	for i := range buf {
		buf[i] = byte(i)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		unix.Close(fd)
	}
	fmt.Println("benign ok", len(buf))
	return 0
}

// growMemory allocates and touches 2 MiB every 100 ms, up to 1 GiB. It is
// not an attack: `minibox ui` runs it under --memory so the live meter
// climbs visibly towards the limit before the OOM kill, which a single
// big allocation (attackMemory) would hide in one jump.
func growMemory() {
	const step, max = 2 << 20, 1 << 30
	for total := step; total <= max; total += step {
		b, err := unix.Mmap(-1, 0, step, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
		if err != nil {
			fmt.Println("mmap:", err)
			os.Exit(2)
		}
		for i := 0; i < step; i += 4096 {
			b[i] = 1 // touch every page so it is really charged to the cgroup
		}
		fmt.Printf("allocated %d MiB\n", total>>20)
		time.Sleep(100 * time.Millisecond)
	}
}

// 1. Mount a filesystem (needs CAP_SYS_ADMIN; mount is the first step of
// many escapes, e.g. mounting a host block device or cgroupfs).
func attackMount([]string) result {
	err := unix.Mount("none", "/mnt", "tmpfs", 0, "size=1m")
	if err == nil {
		unix.Unmount("/mnt", unix.MNT_DETACH)
	}
	return errResult("mount tmpfs on /mnt", err)
}

// 2. Create a new user namespace to regain a full capability set: root in
// a nested namespace has every capability again, undoing a cap drop.
func attackUnshare([]string) result {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS}
	return errResult("clone(CLONE_NEWUSER|CLONE_NEWNS)", cmd.Run())
}

// 3. Load a kernel module. We pass an empty image, so even if every check
// passed the kernel would reject it as invalid (EINVAL/ENOEXEC) rather
// than load anything; EPERM means a permission layer stopped us first.
func attackKernelModule([]string) result {
	_, _, errno := unix.Syscall(unix.SYS_INIT_MODULE, 0, 0, uintptr(unsafe.Pointer(&[]byte{0}[0])))
	switch errno {
	case unix.EPERM, unix.EACCES:
		return blocked("init_module: %v", errno)
	case 0:
		return allowed("init_module succeeded")
	}
	return allowed("init_module passed the permission check (then failed: %v)", errno)
}

// 4. ptrace another process in the container that is not our child (a
// sibling). With ptrace one can read secrets from or inject code into the
// victim. Yama (ptrace_scope=1) allows this only with CAP_SYS_PTRACE.
func attackPtrace([]string) result {
	victim := exec.Command("/proc/self/exe", "sleep")
	if err := victim.Start(); err != nil {
		return result{false, "ERROR start victim: " + err.Error()}
	}
	defer func() { victim.Process.Kill(); victim.Wait() }()
	attacker := exec.Command("/proc/self/exe", "ptrace-attach", strconv.Itoa(victim.Process.Pid))
	out, err := attacker.CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if err == nil {
		return allowed("%s", msg)
	}
	return blocked("%s", msg)
}

func ptraceAttach(pidStr string) int {
	pid, _ := strconv.Atoi(pidStr)
	if err := unix.PtraceAttach(pid); err != nil {
		fmt.Printf("PTRACE_ATTACH to sibling %d: %v", pid, err)
		return 1
	}
	var ws unix.WaitStatus
	unix.Wait4(pid, &ws, unix.WALL, nil)
	unix.PtraceDetach(pid)
	fmt.Printf("attached to sibling %d", pid)
	return 0
}

// 5. Open /proc/sysrq-trigger for writing (could reboot or crash the host).
// We only open it; nothing is ever written.
func attackSysrq([]string) result {
	f, err := os.OpenFile("/proc/sysrq-trigger", os.O_WRONLY, 0)
	if err == nil {
		f.Close()
	}
	return errResult("open /proc/sysrq-trigger for writing (nothing written)", err)
}

// 6. Change a kernel setting through /proc/sys. net.ipv4.ip_forward is
// per network namespace, so even "success" only touches the container's
// own namespace, but it shows /proc/sys is writable.
func attackProcSys([]string) result {
	return errResult("write /proc/sys/net/ipv4/ip_forward",
		os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0))
}

// 7. Read host kernel information that Docker masks (/proc/interrupts:
// host IRQ counts, a side channel on host activity).
func attackKernelInfo([]string) result {
	b, err := os.ReadFile("/proc/interrupts")
	if err != nil {
		return blocked("read /proc/interrupts: %v", err)
	}
	if len(b) == 0 {
		return blocked("/proc/interrupts is empty (masked)")
	}
	return allowed("read %d bytes of host interrupt counters", len(b))
}

// 8. Fork bomb, bounded so it can never hurt the VM: try to hold 500
// processes at once. ALLOWED if all 500 start.
func attackForkBomb([]string) result {
	const target = 500
	var procs []*exec.Cmd
	defer func() {
		for _, p := range procs {
			p.Process.Kill()
			p.Wait()
		}
	}()
	for len(procs) < target {
		c := exec.Command("/bin/sleep", "5")
		if err := c.Start(); err != nil {
			return blocked("started %d/%d processes, then: %v", len(procs), target, err)
		}
		procs = append(procs, c)
	}
	return allowed("held %d processes", target)
}

// 9. Memory exhaustion, bounded at 1 GiB (the VM has more than that free):
// allocate and touch it. Under a memory limit the kernel OOM-kills us
// (the runner sees exit 137 and counts that as BLOCKED).
func attackMemory([]string) result {
	const size = 1 << 30
	b, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return blocked("mmap 1 GiB: %v", err)
	}
	for i := 0; i < size; i += 4096 {
		b[i] = 1
	}
	unix.Munmap(b)
	return allowed("allocated and touched 1 GiB")
}

// 10. Open a raw socket (packet crafting/sniffing, ARP/ICMP spoofing).
func attackRawSocket([]string) result {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err == nil {
		unix.Close(fd)
	}
	return errResult("socket(AF_INET, SOCK_RAW)", err)
}

// 11. Change the hostname (container's own UTS namespace, but the
// operation needs CAP_SYS_ADMIN and should not be allowed by default).
func attackHostname([]string) result {
	return errResult("sethostname", unix.Sethostname([]byte("pwned")))
}

// 12. Set the system clock. We set it to the current time, so even
// "success" would change nothing; the clock is global (not namespaced),
// so the kernel checks CAP_SYS_TIME in the initial user namespace.
func attackClock([]string) result {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_REALTIME, &ts)
	return errResult("clock_settime(CLOCK_REALTIME)", unix.ClockSettime(unix.CLOCK_REALTIME, &ts))
}

// 13. Use the kernel keyring. Keyrings are not fully namespaced, which is
// why Docker blocks keyctl/add_key: keys can leak between containers of the
// same user. The key is revoked straight away.
func attackKeyring([]string) result {
	id, err := unix.AddKey("user", "minibox-probe", []byte("secret"), unix.KEY_SPEC_PROCESS_KEYRING)
	if err != nil {
		return blocked("add_key: %v", err)
	}
	unix.KeyctlInt(unix.KEYCTL_REVOKE, id, 0, 0, 0)
	return allowed("add_key created key %d (revoked)", id)
}

// 14. Use bpf(): loading BPF programs into the kernel has been a rich
// source of privilege escalation bugs.
func attackBPF([]string) result {
	// BPF_MAP_CREATE of a tiny array map: the simplest bpf() command.
	attr := struct{ typ, keySize, valueSize, maxEntries uint32 }{unix.BPF_MAP_TYPE_ARRAY, 4, 4, 1}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_CREATE, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return blocked("bpf(BPF_MAP_CREATE): %v", errno)
	}
	unix.Close(int(fd))
	return allowed("bpf(BPF_MAP_CREATE) succeeded")
}

// 15. Create a block device node for the host disk (8:0 = /dev/sda) to
// read it raw.
func attackMknod([]string) result {
	p := "/tmp/sda"
	err := unix.Mknod(p, unix.S_IFBLK|0o600, int(unix.Mkdev(8, 0)))
	if err != nil {
		return blocked("mknod block device 8:0: %v", err)
	}
	defer os.Remove(p)
	f, err := os.Open(p)
	if err != nil {
		return blocked("mknod worked but opening the disk failed: %v", err)
	}
	f.Close()
	return allowed("created and opened /dev/sda as %s", p)
}

// 16. Classic chroot escape: chroot into a subdirectory while keeping a
// handle outside it, then walk up with "..". Works against chroot-only
// confinement; pivot_root + detaching the old root leaves nothing above.
// args[0] is a path that exists only on the host (the runner passes $HOME).
func attackChrootEscape(args []string) result {
	if len(args) < 1 {
		return result{false, "ERROR need a host-only path"}
	}
	os.MkdirAll("/tmp/jail", 0o755)
	if err := unix.Chroot("/tmp/jail"); err != nil {
		return blocked("chroot: %v", err)
	}
	// Our cwd is still outside the new root: climb from it.
	for i := 0; i < 64; i++ {
		unix.Chdir("..")
	}
	if err := unix.Chroot("."); err != nil {
		return blocked("second chroot: %v", err)
	}
	if _, err := os.Stat(args[0]); err == nil {
		return allowed("reached host path %s", args[0])
	}
	return blocked("chroot worked, but \"..\" stops at the container root (%s not found)", args[0])
}

// 17. Read another container's files. The runner starts a second container
// that writes args[0] (a random token) to /secret, and passes its host
// state directory as args[1]. We look via /proc/*/root (other processes'
// roots) and via the host path of its overlay.
func attackOtherContainer(args []string) result {
	if len(args) < 2 {
		return result{false, "ERROR need token and state dir"}
	}
	token, stateDir := args[0], args[1]
	candidates, _ := filepath.Glob("/proc/[0-9]*/root/secret")
	candidates = append(candidates,
		filepath.Join(stateDir, "upper/secret"), filepath.Join(stateDir, "merged/secret"))
	for _, c := range candidates {
		if b, err := os.ReadFile(c); err == nil && strings.Contains(string(b), token) {
			return allowed("read the other container's secret via %s", c)
		}
	}
	var pe *os.PathError
	_, err := os.Stat(stateDir)
	if errors.As(err, &pe) {
		return blocked("other container invisible: %s: %v; no /proc/*/root/secret", stateDir, pe.Err)
	}
	return blocked("secret not readable")
}
