package ui

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testServer builds a Server around a fake image directory.
func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "img", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Dir: dir, Image: "img", Exe: "/bin/false", StateDir: t.TempDir(),
		AttackPolicy: filepath.Join(dir, "missing.json")})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidateOnlyOfferedChoices(t *testing.T) {
	s := testServer(t)
	a := s.actions["memory"]
	if p, err := a.validate(nil); err != nil || p["limit"] != "64m" {
		t.Errorf("default: got %v, %v; want limit=64m", p, err)
	}
	if _, err := a.validate(map[string]string{"limit": "32m"}); err != nil {
		t.Errorf("listed choice rejected: %v", err)
	}
	for _, bad := range []map[string]string{
		{"limit": "9g"},                    // not offered
		{"limit": "64m; rm -rf /"},         // shell syntax is just an unknown value
		{"limit": "64m", "image": "/"},     // unknown parameter
		{"limit": "64m", "--security": ""}, // flags can't be smuggled in either
	} {
		if _, err := a.validate(bad); err == nil {
			t.Errorf("validate(%v) accepted", bad)
		}
	}
}

func TestCatalogueHidesMissingWorkloads(t *testing.T) {
	s := testServer(t) // no probe, no bench image
	for _, c := range s.actions["profile"].Params[0].Choices {
		if c.Value == "benign" || c.Value == "python" {
			t.Errorf("workload %q offered without its image/probe", c.Value)
		}
	}
}

func TestGuard(t *testing.T) {
	s := testServer(t)
	h := s.Handler()
	cases := []struct {
		name, method, path, host string
		header                   bool
		want                     int
	}{
		{"page on localhost", "GET", "/", "localhost:7070", false, 200},
		{"info on IPv4", "GET", "/api/info", "127.0.0.1:7070", false, 200},
		{"info on IPv6", "GET", "/api/info", "[::1]:7070", false, 200},
		{"DNS rebinding host", "GET", "/api/info", "evil.example:7070", false, 403},
		{"POST without header", "POST", "/api/stop", "127.0.0.1:7070", false, 403},
		{"POST with header", "POST", "/api/stop", "127.0.0.1:7070", true, 200},
		{"unknown action", "POST", "/api/run", "127.0.0.1:7070", true, 404},
	}
	for _, c := range cases {
		body := strings.NewReader(`{"action":"nope"}`)
		r := httptest.NewRequest(c.method, c.path, body)
		r.Host = c.host
		if c.header {
			r.Header.Set("X-Minibox-UI", "1")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: status %d, want %d (%s)", c.name, w.Code, c.want, strings.TrimSpace(w.Body.String()))
		}
	}
}

func TestFilterEndpoint(t *testing.T) {
	s := testServer(t)
	get := func(q string) map[string]any {
		r := httptest.NewRequest("GET", "/api/filter?"+q, nil)
		r.Host = "127.0.0.1"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: status %d: %s", q, w.Code, w.Body.String())
		}
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	cases := map[string]string{
		"source=baseline&syscall=getpid":                "ALLOW",
		"source=baseline&syscall=mount":                 "ERRNO(EPERM)",
		"source=baseline&syscall=clone&variant=fork":    "ALLOW",
		"source=baseline&syscall=clone&variant=newuser": "ERRNO(EPERM)",
	}
	for q, want := range cases {
		trace := get(q)["trace"].(map[string]any)
		if trace["result"] != want {
			t.Errorf("%s: result %v, want %s", q, trace["result"], want)
		}
	}
}

func TestAttackOutcome(t *testing.T) {
	cases := []struct {
		res          cmdResult
		status, want string
	}{
		{cmdResult{Code: 0, Out: []string{"BLOCKED mount: operation not permitted"}}, "BLOCKED", "mount: operation not permitted"},
		{cmdResult{Code: 1, Out: []string{"ALLOWED raw socket opened"}}, "ALLOWED", "raw socket opened"},
		{cmdResult{Code: 137, Err: []string{"minibox: 1 process(es) killed for exceeding --memory 256m"}}, "BLOCKED", "killed: 1 process(es) killed"},
		{cmdResult{Code: 127, Err: []string{"something broke"}}, "ERROR", "something broke"},
	}
	for _, c := range cases {
		st, d := attackOutcome(c.res)
		if st != c.status || !strings.HasPrefix(d, c.want) {
			t.Errorf("attackOutcome(%+v) = %s %q, want %s %q...", c.res, st, d, c.status, c.want)
		}
	}
}

func TestCgroupFileParsing(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("memory.current", "1048576\n")
	write("memory.max", "max\n")
	write("pids.current", "3\n")
	write("pids.max", "20\n")
	write("cpu.stat", "usage_usec 5000\nuser_usec 4000\nnr_throttled 7\n")
	write("cpu.max", "50000 100000\n")
	write("memory.events", "low 0\noom 1\noom_kill 1\n")
	write("pids.events", "max 4\n")
	m, err := readMeter(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := Meter{MemBytes: 1 << 20, MemMax: 0, Pids: 3, PidsMax: 20, CPUUsec: 5000, CPULimit: 0.5,
		Throttled: 7, OOMKills: 1, PidsRejected: 4}
	if m != want {
		t.Errorf("readMeter = %+v\nwant        %+v", m, want)
	}
	os.Remove(filepath.Join(dir, "memory.current"))
	if _, err := readMeter(dir); err == nil {
		t.Error("readMeter succeeded on a removed cgroup")
	}
}

func TestHostViewHasEveryFact(t *testing.T) {
	hv := hostView()
	for _, f := range isolationFacts {
		if hv[f.Key] == "" {
			t.Errorf("host view lacks %s", f.Key)
		}
	}
	kv := parseKV([]string{"uid=0", "uid_map=0 1000 1", "noise", "hostname=demo"})
	if kv["uid_map"] != "0 1000 1" || kv["hostname"] != "demo" || len(kv) != 3 {
		t.Errorf("parseKV = %v", kv)
	}
}
