// Command loadgen is a minimal closed-loop HTTP load generator for the
// Phase 6 benchmarks: N workers each send requests back to back for a fixed
// duration. It prints one JSON object with throughput and latency.
//
// Every request opens a new connection (no keep-alive), because Python's
// http.server and busybox httpd both close the connection after each
// response anyway; this keeps all workloads comparable.
//
// Usage: loadgen -url http://127.0.0.1:8080/ -c 8 -d 10s [-warmup 1s]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

type result struct {
	Requests   int     `json:"requests"`
	Errors     int     `json:"errors"`
	Seconds    float64 `json:"seconds"`
	RPS        float64 `json:"rps"`
	LatMeanMs  float64 `json:"lat_mean_ms"`
	LatP50Ms   float64 `json:"lat_p50_ms"`
	LatP99Ms   float64 `json:"lat_p99_ms"`
	LatMaxMs   float64 `json:"lat_max_ms"`
	Slow       int     `json:"slow_over_500ms"` // usually a dropped SYN retried after ~1 s
	Concurrent int     `json:"concurrency"`
}

func main() {
	url := flag.String("url", "", "URL to request")
	conc := flag.Int("c", 8, "concurrent workers")
	dur := flag.Duration("d", 10*time.Second, "measurement duration")
	warmup := flag.Duration("warmup", time.Second, "unmeasured warm-up before measuring")
	flag.Parse()
	if *url == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -url is required")
		os.Exit(2)
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	get := func() error {
		resp, err := client.Get(*url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		return nil
	}

	// Warm up: fill caches, start lazily-created threads in the server.
	for end := time.Now().Add(*warmup); time.Now().Before(end); {
		get()
	}

	var mu sync.Mutex
	var lats []time.Duration
	errors := 0
	start := time.Now()
	deadline := start.Add(*dur)
	var wg sync.WaitGroup
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var mine []time.Duration
			myErrs := 0
			for time.Now().Before(deadline) {
				t := time.Now()
				if err := get(); err != nil {
					myErrs++
					continue
				}
				mine = append(mine, time.Since(t))
			}
			mu.Lock()
			lats = append(lats, mine...)
			errors += myErrs
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	r := result{Requests: len(lats), Errors: errors, Seconds: elapsed, Concurrent: *conc}
	if len(lats) > 0 {
		sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
		var sum time.Duration
		for _, l := range lats {
			sum += l
		}
		ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
		r.RPS = float64(len(lats)) / elapsed
		r.LatMeanMs = ms(sum / time.Duration(len(lats)))
		r.LatP50Ms = ms(lats[len(lats)/2])
		r.LatP99Ms = ms(lats[len(lats)*99/100])
		r.LatMaxMs = ms(lats[len(lats)-1])
		for _, l := range lats {
			if l > 500*time.Millisecond {
				r.Slow++
			}
		}
	}
	json.NewEncoder(os.Stdout).Encode(r)
}
