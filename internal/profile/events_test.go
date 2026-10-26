package profile

import (
	"bytes"
	"encoding/json"
	"testing"

	"golang.org/x/sys/unix"
)

// TestEventsFirstSightingOnly checks that repeated syscalls and paths are
// reported once, so a busy program doesn't flood the live view.
func TestEventsFirstSightingOnly(t *testing.T) {
	var buf bytes.Buffer
	r := newRecorder()
	r.events = newEventSink(&buf)

	for range 3 {
		r.onExit(event{nr: unix.SYS_GETPID})
	}
	read := []pathArg{{path: "/etc/os-release", kind: pathRead}}
	r.onExit(event{nr: unix.SYS_STAT, paths: read})
	r.onExit(event{nr: unix.SYS_STAT, paths: read})
	r.events.progress(r.total, true)

	var kinds = map[string]int{}
	var last Event
	dec := json.NewDecoder(&buf)
	for dec.More() {
		var e Event // fresh each time: Decode leaves absent fields untouched
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		kinds[e.Kind+":"+e.Name+e.Path]++
		last = e
	}
	want := map[string]int{"syscall:getpid": 1, "syscall:stat": 1, "path:/etc/os-release": 1}
	for k, n := range want {
		if kinds[k] != n {
			t.Errorf("%s reported %d times, want %d (all: %v)", k, kinds[k], n, kinds)
		}
	}
	if last.Kind != "progress" || last.Total != 5 {
		t.Errorf("last event = %+v, want progress with total 5", last)
	}
}

// TestNilSink checks that profiling without --events works (no panics).
func TestNilSink(t *testing.T) {
	r := newRecorder()
	r.onExit(event{nr: unix.SYS_GETPID})
	r.events.progress(r.total, true)
}
