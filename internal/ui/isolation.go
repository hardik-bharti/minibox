package ui

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// isolationFacts are the rows of the side-by-side isolation view, in
// display order. The container side prints the same keys (isolationScript)
// so both columns come from the same kind of source.
var isolationFacts = []struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Why   string `json:"why"`
}{
	{"ns_user", "User namespace", "UID 0 inside is your UID outside"},
	{"ns_mnt", "Mount namespace", "its own list of mounts"},
	{"ns_pid", "PID namespace", "its own process numbering"},
	{"ns_uts", "UTS namespace", "its own hostname"},
	{"ns_ipc", "IPC namespace", "its own SysV IPC and message queues"},
	{"ns_net", "Network namespace", "its own interfaces and ports"},
	{"uid", "User ID", "root inside, you outside"},
	{"uid_map", "uid_map", "container 0 maps to host UID, size 1"},
	{"pid", "Own PID", "the command is PID 1 in its namespace"},
	{"procs", "Processes visible", "host processes are hidden"},
	{"hostname", "Hostname", "set with sethostname in the UTS namespace"},
	{"root_fs", "Root filesystem", "overlay over the read-only image"},
	{"mounts", "Mounts visible", "only the container's own"},
	{"ifaces", "Network interfaces", "only loopback (--net none)"},
	{"home", "Your home directory", "the host filesystem is gone after pivot_root"},
}

// isolationScript prints the container's view as KEY=VALUE lines. $$ is
// the shell itself, which is PID 1 because it is the container's command.
func isolationScript(home string) string {
	return strings.Join([]string{
		`for n in user mnt pid uts ipc net; do echo "ns_$n=$(readlink /proc/self/ns/$n)"; done`,
		`echo "uid=$(id -u)"`,
		`echo "uid_map=$(tr -s ' ' < /proc/self/uid_map | sed 's/^ //')"`,
		`echo "pid=$$"`,
		`echo "procs=$(ls -d /proc/[0-9]* | wc -l)"`,
		`echo "hostname=$(hostname)"`,
		`echo "root_fs=$(awk '$2 == "/" {print $3}' /proc/mounts)"`,
		`echo "mounts=$(wc -l < /proc/mounts)"`,
		`echo "ifaces=$(ls /sys/class/net | tr '\n' ' ')"`,
		`[ -e '` + home + `' ] && echo "home=visible" || echo "home=not found"`,
	}, "\n")
}

// parseKV reads KEY=VALUE lines.
func parseKV(lines []string) map[string]string {
	m := map[string]string{}
	for _, l := range lines {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// hostView collects the same facts for the server's own process, i.e.
// what an ordinary process on the host sees.
func hostView() map[string]string {
	m := map[string]string{}
	for _, n := range []string{"user", "mnt", "pid", "uts", "ipc", "net"} {
		m["ns_"+n], _ = os.Readlink("/proc/self/ns/" + n)
	}
	m["uid"] = strconv.Itoa(os.Getuid())
	if b, err := os.ReadFile("/proc/self/uid_map"); err == nil {
		m["uid_map"] = strings.Join(strings.Fields(string(b)), " ")
	}
	m["pid"] = strconv.Itoa(os.Getpid())
	procs, _ := filepath.Glob("/proc/[0-9]*")
	m["procs"] = strconv.Itoa(len(procs))
	m["hostname"], _ = os.Hostname()
	m["root_fs"], m["mounts"] = mountFacts()
	var names []string
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			names = append(names, i.Name)
		}
	}
	m["ifaces"] = strings.Join(names, " ")
	m["home"] = "visible"
	return m
}

// mountFacts returns the root filesystem type and the number of mounts.
func mountFacts() (rootFS, count string) {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	n := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		n++
		if fields := strings.Fields(s.Text()); len(fields) >= 3 && fields[1] == "/" {
			rootFS = fields[2]
		}
	}
	return rootFS, strconv.Itoa(n)
}
