package ui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/hardik-bharti/minibox/internal/security"
)

//go:embed static
var staticFiles embed.FS

// Config says where things are. Relative paths are resolved against Dir.
type Config struct {
	Addr         string // listen address, e.g. 127.0.0.1:7070
	Exe          string // the minibox binary to run for each demo
	Dir          string // working directory (the repository root)
	Image        string // images/alpine
	BenchImage   string // images/bench (optional)
	Probe        string // tests/attacks/bin/probe (optional)
	AttackPolicy string // results/policies/attack-probe.json (optional)
	StateDir     string // scratch space for generated policies
}

// Server is the dashboard's HTTP server.
type Server struct {
	cfg     Config
	hub     *hub
	actions map[string]*Action
	order   []*Action
	have    struct{ bench, probe bool }

	mu     sync.Mutex
	cur    *job // the running job, if any
	nextID int

	pmu      sync.Mutex
	policies map[string]string // workload ID -> generated policy file
}

// New checks the configuration and builds the server.
func New(cfg Config) (*Server, error) {
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(cfg.Dir, p)
	}
	cfg.Image, cfg.BenchImage, cfg.Probe = abs(cfg.Image), abs(cfg.BenchImage), abs(cfg.Probe)
	cfg.AttackPolicy = abs(cfg.AttackPolicy)
	if fi, err := os.Stat(cfg.Image); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("image %s not found: run `make image` first", cfg.Image)
	}
	s := &Server{cfg: cfg, hub: newHub(), actions: map[string]*Action{}, policies: map[string]string{}}
	if _, err := os.Stat(filepath.Join(cfg.BenchImage, "usr", "bin", "python3")); err == nil {
		s.have.bench = true
	}
	if fi, err := os.Stat(cfg.Probe); err == nil && fi.Mode().IsRegular() {
		s.have.probe = true
	}
	for _, a := range s.catalogue() {
		s.actions[a.ID] = a
		s.order = append(s.order, a)
	}
	return s, nil
}

// Handler returns the HTTP routes, wrapped in the safety checks.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.Handle("GET /api/events", s.hub)
	mux.HandleFunc("GET /api/info", s.handleInfo)
	mux.HandleFunc("GET /api/filter", s.handleFilter)
	mux.HandleFunc("POST /api/run", s.handleRun)
	mux.HandleFunc("POST /api/stop", s.handleStop)
	return guard(mux)
}

// guard protects the API from other websites open in the same browser.
//
//   - Host check: only "localhost" or an IP literal. A malicious page could
//     point its own domain at 127.0.0.1 (DNS rebinding) to talk to us as
//     same-origin; the browser would then send that domain as the Host.
//   - POST needs the X-Minibox-UI header. Another site can't add a custom
//     header to a cross-origin request without a CORS preflight, which we
//     never approve, so it can't start demos even blindly.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedHost(r.Host) {
			http.Error(w, "unexpected Host header", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && r.Header.Get("X-Minibox-UI") != "1" {
			http.Error(w, "missing X-Minibox-UI header", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "+
			"font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func allowedHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.Trim(host, "[]")
	return host == "localhost" || net.ParseIP(host) != nil
}

// info is everything the page needs to draw itself.
type info struct {
	Actions       []*Action         `json:"actions"`
	Have          map[string]bool   `json:"have"`
	Docker        []string          `json:"docker_syscalls"`
	AttackNames   []string          `json:"attacks"`
	AttackWhat    map[string]string `json:"attack_descriptions"`
	Policies      []string          `json:"policies"`
	Running       *jobInfo          `json:"running,omitempty"`
	Image         string            `json:"image"`
	FilterSources []string          `json:"filter_sources"`
}

type jobInfo struct {
	ID     int    `json:"id"`
	Action string `json:"action"`
	Panel  string `json:"panel"`
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	docker, err := security.DockerFilter(security.DefaultCaps)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	in := info{
		Actions: s.order, Docker: docker.Syscalls(), Image: s.cfg.Image,
		Have:       map[string]bool{"bench": s.have.bench, "probe": s.have.probe},
		AttackWhat: map[string]string{},
	}
	for _, a := range attacks {
		in.AttackNames = append(in.AttackNames, a.Name)
		in.AttackWhat[a.Name] = a.What
	}
	in.Policies = s.policyIDs()
	in.FilterSources = s.filterSources()
	s.mu.Lock()
	if s.cur != nil {
		in.Running = &jobInfo{ID: s.cur.id, Action: s.cur.action, Panel: s.cur.panel}
	}
	s.mu.Unlock()
	writeJSON(w, in)
}

// handleRun starts an action if none is running.
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string            `json:"action"`
		Params map[string]string `json:"params"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	a, ok := s.actions[req.Action]
	if !ok {
		http.Error(w, "unknown action", http.StatusNotFound)
		return
	}
	params, err := a.validate(req.Params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if s.cur != nil {
		s.mu.Unlock()
		http.Error(w, "another demo is running; stop it or wait for it to finish", http.StatusConflict)
		return
	}
	s.nextID++
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{id: s.nextID, panel: a.Panel, action: a.ID, s: s, ctx: ctx, cancel: cancel}
	s.cur = j
	s.mu.Unlock()

	go s.runJob(j, a, params)
	writeJSON(w, map[string]int{"job": j.id})
}

func (s *Server) runJob(j *job, a *Action, params map[string]string) {
	j.send(Msg{Type: "job", State: "start", Action: a.ID, Title: a.Title})
	err := a.run(j, params)
	end := Msg{Type: "job", State: "end", Action: a.ID}
	if err != nil {
		end.Error = err.Error()
	}
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
	j.cancel()
	j.send(end)
}

func (s *Server) handleStop(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	j := s.cur
	s.mu.Unlock()
	if j != nil {
		j.cancel()
	}
	writeJSON(w, map[string]bool{"stopping": j != nil})
}

// Stop cancels the running job, for a clean shutdown.
func (s *Server) Stop() {
	s.mu.Lock()
	j := s.cur
	s.mu.Unlock()
	if j != nil {
		j.cancel()
	}
}

// Idle reports whether no job is running.
func (s *Server) Idle() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur == nil
}

func (s *Server) setPolicy(id, path string) {
	s.pmu.Lock()
	s.policies[id] = path
	s.pmu.Unlock()
}

func (s *Server) policy(id string) (string, bool) {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	p, ok := s.policies[id]
	return p, ok
}

func (s *Server) policyIDs() []string {
	s.pmu.Lock()
	defer s.pmu.Unlock()
	ids := make([]string, 0, len(s.policies))
	for id := range s.policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// filterSources are the filters the "inside the filter" panel can show:
// Docker's baseline, the evaluation's attack policy, and every policy
// profiled in this session.
func (s *Server) filterSources() []string {
	out := []string{"baseline"}
	if _, ok := s.attackPolicyFile(); ok {
		out = append(out, "attack-probe")
	}
	for _, id := range s.policyIDs() {
		if id != "attack-probe" {
			out = append(out, "workload:"+id)
		}
	}
	return out
}

// handleFilter compiles a filter exactly as `minibox run` would and shows
// one syscall's path through it. It only computes, so it is a GET.
func (s *Server) handleFilter(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cfg, err := s.filterConfig(q.Get("source"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f, err := cfg.SeccompFilter()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	prog, err := f.Compile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := q.Get("syscall")
	nr, ok := security.SyscallNumber(name)
	if !ok {
		http.Error(w, "unknown syscall", http.StatusBadRequest)
		return
	}
	var args [6]uint64
	label := name + "()"
	if name == "clone" {
		args[0], label = uint64(unix.SIGCHLD), "clone(SIGCHLD): an ordinary fork"
		if q.Get("variant") == "newuser" {
			args[0], label = unix.CLONE_NEWUSER, "clone(CLONE_NEWUSER): a new user namespace"
		}
	}
	ret, path, err := security.Evaluate(prog, nr, args)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"source": q.Get("source"), "allowed": f.Syscalls(), "instructions": security.Disassemble(prog),
		"trace": map[string]any{"syscall": name, "nr": nr, "label": label, "path": path, "result": security.RetName(ret)},
	})
}

func (s *Server) filterConfig(source string) (security.Config, error) {
	switch {
	case source == "baseline":
		return security.NewBaseline(), nil
	case source == "attack-probe":
		if p, ok := s.attackPolicyFile(); ok {
			return loadPolicyConfig(p)
		}
	case strings.HasPrefix(source, "workload:"):
		if p, ok := s.policy(strings.TrimPrefix(source, "workload:")); ok {
			return loadPolicyConfig(p)
		}
	}
	return security.Config{}, errors.New("unknown filter source")
}

// attackPolicyFile is the evaluation's policy, or the one generated in
// this session if `make attacks` hasn't been run.
func (s *Server) attackPolicyFile() (string, bool) {
	if _, err := os.Stat(s.cfg.AttackPolicy); err == nil {
		return s.cfg.AttackPolicy, true
	}
	return s.policy("attack-probe")
}

func loadPolicyConfig(path string) (security.Config, error) {
	p, err := security.LoadPolicy(path)
	if err != nil {
		return security.Config{}, err
	}
	return security.NewFromPolicy(p), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
