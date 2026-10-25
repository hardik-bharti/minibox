package network

import "testing"

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": None, "none": None, "bridge": Bridge} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"host", "Bridge", "slirp"} {
		if _, err := ParseMode(in); err == nil {
			t.Errorf("ParseMode(%q) succeeded, want error", in)
		}
	}
}

func TestParsePort(t *testing.T) {
	good := map[string]Port{
		"8080:80":     {8080, 80, "tcp"},
		"8080:80/tcp": {8080, 80, "tcp"},
		"5353:53/udp": {5353, 53, "udp"},
		"65535:1":     {65535, 1, "tcp"},
	}
	for in, want := range good {
		got, err := ParsePort(in)
		if err != nil || got != want {
			t.Errorf("ParsePort(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	bad := []string{"", "80", "80:", ":80", "0:80", "80:70000", "a:b", "80:80/sctp", "1:2:3"}
	for _, in := range bad {
		if p, err := ParsePort(in); err == nil {
			t.Errorf("ParsePort(%q) = %v, want error", in, p)
		}
	}
}
