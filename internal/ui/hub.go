package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Msg is one update sent to every open page. Type says how to read it:
//
//	job     a job started or ended (State "start" | "end")
//	cmd     a minibox command started (Argv)
//	line    one line of output (Stream "out" | "err")
//	exit    a minibox command ended (Code, Ms)
//	meter   a cgroup reading (Meter)
//	profile a live profiler observation (Data)
//	result  a structured result for the panel (Data)
type Msg struct {
	Type   string   `json:"type"`
	Job    int      `json:"job"`
	Panel  string   `json:"panel,omitempty"`
	Action string   `json:"action,omitempty"`
	Title  string   `json:"title,omitempty"`
	State  string   `json:"state,omitempty"`
	Argv   []string `json:"argv,omitempty"`
	Stream string   `json:"stream,omitempty"`
	Text   string   `json:"text,omitempty"`
	Code   *int     `json:"code,omitempty"`
	Ms     int64    `json:"ms,omitempty"`
	Error  string   `json:"error,omitempty"`
	Meter  *Meter   `json:"meter,omitempty"`
	Data   any      `json:"data,omitempty"`
}

// hub fans messages out to every connected page (server-sent events).
type hub struct {
	mu      sync.Mutex
	clients map[chan []byte]bool
}

func newHub() *hub { return &hub{clients: map[chan []byte]bool{}} }

// send delivers m to every client. A client that can't keep up loses
// messages rather than blocking the job: its buffer is 512 messages, far
// more than a demo produces between two browser reads.
func (h *hub) send(m Msg) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c <- b:
		default:
		}
	}
}

// ServeHTTP streams messages to one page until it disconnects.
func (h *hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	c := make(chan []byte, 512)
	h.mu.Lock()
	h.clients[c] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	// A comment line every 15 s keeps proxies (and SSH tunnels) from
	// closing an idle stream.
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case b := <-c:
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
