package profile

import (
	"encoding/json"
	"io"
	"time"
)

// Event is one live observation, written as a JSON line while profiling
// (`minibox profile --events FILE`). `minibox ui` tails the file to show
// syscalls appearing as the program makes them.
//
// Only the *first* sighting of each syscall, path and capability is sent,
// plus a running total at most every progressEvery. A busy program makes
// hundreds of thousands of syscalls; one line per call would slow the
// traced program down far more than ptrace already does.
type Event struct {
	T      int64  `json:"t_ms"`             // milliseconds since profiling started
	Kind   string `json:"kind"`             // syscall | path | cap | progress
	Name   string `json:"name,omitempty"`   // syscall or capability name
	Path   string `json:"path,omitempty"`   // path events
	Access string `json:"access,omitempty"` // read | write (path events)
	Reason string `json:"reason,omitempty"` // why a capability was inferred
	Total  int    `json:"total,omitempty"`  // syscalls recorded so far (progress)
}

const progressEvery = 200 * time.Millisecond

// eventSink encodes events to w. A nil sink (no --events) does nothing,
// so the recorder can call it unconditionally.
type eventSink struct {
	enc      *json.Encoder
	start    time.Time
	lastProg time.Time
	failed   bool
}

func newEventSink(w io.Writer) *eventSink {
	if w == nil {
		return nil
	}
	return &eventSink{enc: json.NewEncoder(w), start: time.Now()}
}

func (s *eventSink) emit(e Event) {
	if s == nil || s.failed {
		return
	}
	e.T = time.Since(s.start).Milliseconds()
	// If the reader went away, stop writing rather than fail the profile:
	// the policy is what matters, the live view is a bonus.
	if err := s.enc.Encode(e); err != nil {
		s.failed = true
	}
}

// progress sends the running total, throttled to one line per progressEvery.
func (s *eventSink) progress(total int, force bool) {
	if s == nil {
		return
	}
	if now := time.Now(); force || now.Sub(s.lastProg) >= progressEvery {
		s.lastProg = now
		s.emit(Event{Kind: "progress", Total: total})
	}
}
