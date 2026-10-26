// Package ui implements `minibox ui`: a small web dashboard for demos and
// the viva. It shows the OS concepts live, using real kernel data.
//
// Design:
//   - The server never builds containers itself. Every demo runs the real
//     CLI (`minibox run ...`, `minibox profile ...`) as a child process,
//     and the page shows that exact command line. What you see in the
//     browser is what you would get in a terminal.
//   - Only a fixed catalogue of actions exists (actions.go). Parameters are
//     picked from fixed lists, so the page can't be used to run arbitrary
//     commands, even by another website open in the same browser.
//   - Live data comes from where the kernel publishes it: the container's
//     cgroup files (cgwatch.go) and the profiler's event log (--events).
//     Updates reach the browser over server-sent events (hub.go).
//   - One job runs at a time. Demos are short, and running them one by one
//     keeps every meter about exactly one container.
//
// Only the Go standard library is used; the page is plain HTML, CSS and JS
// embedded in the binary (static/).
package ui
