package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunDispatch(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{"no args prints usage", nil, 2, "", "Usage:"},
		{"help", []string{"help"}, 0, "Usage:", ""},
		{"version", []string{"version"}, 0, "minibox dev", ""},
		{"unknown command", []string{"frobnicate"}, 2, "", `unknown command "frobnicate"`},
		{"run without args shows run usage", []string{"run"}, 2, "", "Usage: minibox run"},
		{"run with missing command", []string{"run", "/"}, 2, "", "Usage: minibox run"},
		{"run with missing rootfs", []string{"run", "/does/not/exist", "sh"}, 1, "", "rootfs"},
		{"bad --net rejected", []string{"run", "--net", "host", "/", "sh"}, 1, "", "invalid --net"},
		{"bad -p rejected", []string{"run", "--net", "bridge", "-p", "80", "/", "sh"}, 2, "", "HOST:CONTAINER"},
		{"-p without bridge rejected", []string{"run", "-p", "8080:80", "/", "sh"}, 1, "", "needs --net=bridge"},
		{"bad --security rejected", []string{"run", "--security", "max", "/", "sh"}, 1, "", "invalid --security"},
		{"--policy with --security rejected", []string{"run", "--security", "none", "--policy", "x.json", "/", "sh"}, 1, "", "mutually exclusive"},
		{"missing policy file", []string{"run", "--policy", "/does/not/exist.json", "/", "sh"}, 1, "", "no such file"},
		{"profile without args shows profile usage", []string{"profile"}, 2, "", "Usage: minibox profile"},
		{"profile rejects --security", []string{"profile", "--security", "none", "/", "sh"}, 2, "", "not defined"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)

			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
			if !strings.Contains(stdout.String(), tc.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tc.wantStdout)
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}
