// Package cgroups puts a container in its own cgroup v2 group and applies
// --memory, --cpus and --pids limits.
//
// Rootless detail: an unprivileged user may only create cgroups inside a
// subtree systemd has delegated to them, and may only move a process between
// two cgroups if it can write to their common ancestor. A login shell lives
// in a root-owned session scope, so minibox first re-executes itself in a
// delegated transient scope (systemd-run --user --scope -p Delegate=yes)
// and builds the container cgroup inside that.
package cgroups
