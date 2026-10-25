#!/usr/bin/env bash
# check-env.sh: verify this machine can run minibox.
#
# Each check prints PASS, WARN or FAIL with a hint on how to fix it.
# A WARN means a later phase or optional feature may be affected; a FAIL
# means minibox cannot work at all. Exit status is 1 if anything FAILed.
#
# Checks are *functional* where possible (e.g. we actually try to mount
# overlayfs inside a user namespace) because a config flag being set does
# not guarantee the feature works for an unprivileged user.

set -u

fails=0
warns=0

pass() { printf '  [PASS] %s\n' "$1"; }
warn() { printf '  [WARN] %s\n         -> %s\n' "$1" "$2"; warns=$((warns + 1)); }
fail() { printf '  [FAIL] %s\n         -> %s\n' "$1" "$2"; fails=$((fails + 1)); }

# Scratch space for functional tests, removed on exit.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

check_not_root() {
    # minibox is a *rootless* runtime; running checks as root would hide
    # exactly the permission problems we are trying to detect.
    if [ "$(id -u)" -eq 0 ]; then
        fail "running as root" "run this script as your normal user"
    else
        pass "running as unprivileged user $(id -un) (uid $(id -u))"
    fi
}

check_kernel() {
    local rel major minor
    rel=$(uname -r)
    major=${rel%%.*}
    minor=${rel#*.}; minor=${minor%%.*}
    # 5.11 is the first kernel that allows overlayfs mounts inside an
    # unprivileged user namespace, which our rootless design depends on.
    if [ "$major" -gt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -ge 11 ]; }; then
        pass "kernel $rel (>= 5.11)"
    else
        fail "kernel $rel is older than 5.11" "upgrade the kernel; rootless overlayfs needs >= 5.11"
    fi
}

check_go() {
    if command -v go >/dev/null 2>&1; then
        pass "$(go version)"
    else
        fail "go not found in PATH" "install Go 1.27+ and add it to PATH"
    fi
}

check_cgroup_v2() {
    local fstype
    fstype=$(stat -fc %T /sys/fs/cgroup 2>/dev/null)
    if [ "$fstype" = "cgroup2fs" ]; then
        pass "cgroups v2 (unified hierarchy) mounted at /sys/fs/cgroup"
    else
        fail "/sys/fs/cgroup is '$fstype', not cgroup2fs" \
             "boot with systemd.unified_cgroup_hierarchy=1"
        return
    fi

    # Rootless containers can only create cgroups inside the subtree systemd
    # delegates to our user. The controllers enabled there decide which
    # limits (--memory, --cpus, --pids) we can apply in Phase 2.
    local uid ctl
    uid=$(id -u)
    ctl="/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/cgroup.subtree_control"
    if [ ! -r "$ctl" ]; then
        warn "no delegated cgroup for this user ($ctl)" \
             "log in through a normal systemd session (ssh/console), not 'su'"
        return
    fi
    local c missing=""
    for c in cpu memory pids; do
        grep -qw "$c" "$ctl" || missing="$missing $c"
    done
    if [ -z "$missing" ]; then
        pass "delegated cgroup controllers: $(cat "$ctl")"
    else
        warn "controllers not delegated to user:$missing" \
             "create /etc/systemd/system/user@.service.d/delegate.conf with '[Service]' and 'Delegate=cpu cpuset io memory pids', then reboot"
    fi
}

check_userns() {
    local v
    v=$(sysctl -n user.max_user_namespaces 2>/dev/null || echo 0)
    if [ "$v" -gt 0 ]; then
        pass "user.max_user_namespaces = $v"
    else
        fail "user.max_user_namespaces = $v" "sudo sysctl -w user.max_user_namespaces=15000"
    fi

    # Debian/Ubuntu specific switch; absent on other distros, which is fine.
    v=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo absent)
    if [ "$v" = "0" ]; then
        fail "kernel.unprivileged_userns_clone = 0" "sudo sysctl -w kernel.unprivileged_userns_clone=1"
    fi

    # Ubuntu 23.10+ blocks unprivileged user namespaces via AppArmor by default.
    v=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)
    if [ "$v" = "1" ]; then
        fail "kernel.apparmor_restrict_unprivileged_userns = 1" \
             "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 (persist in /etc/sysctl.d/)"
    fi

    # The real test: can we become "root" in a new user namespace?
    if [ "$(unshare --user --map-root-user id -u 2>/dev/null)" = "0" ]; then
        pass "unprivileged user namespace works (mapped to uid 0 inside)"
    else
        fail "cannot create an unprivileged user namespace" \
             "check the sysctls above and any AppArmor/SELinux policy"
    fi
}

check_overlayfs() {
    # overlay may be a module (CONFIG_OVERLAY_FS=m) that the kernel loads on
    # first use, so we don't rely on /proc/filesystems; we just try it.
    mkdir -p "$tmp"/{lower,upper,work,merged}
    echo hi > "$tmp/lower/f"
    if unshare --user --map-root-user --mount sh -c \
        "mount -t overlay overlay -o lowerdir=$tmp/lower,upperdir=$tmp/upper,workdir=$tmp/work $tmp/merged && cat $tmp/merged/f" \
        >/dev/null 2>&1; then
        pass "overlayfs can be mounted inside a rootless user namespace"
    else
        fail "overlayfs mount failed inside user namespace" \
             "run 'sudo modprobe overlay' and add 'overlay' to /etc/modules-load.d/overlay.conf"
    fi
}

check_subids() {
    # Optional: subordinate UID/GID ranges + newuidmap let a container use
    # many UIDs. minibox maps only container root -> your user, so this is
    # not required.
    local me
    me=$(id -un)
    if command -v newuidmap >/dev/null 2>&1 && grep -q "^$me:" /etc/subuid 2>/dev/null; then
        pass "newuidmap + /etc/subuid range present (multi-UID mapping possible)"
    else
        warn "newuidmap or /etc/subuid entry missing (optional)" \
             "only needed for multi-UID mappings: sudo apt install uidmap"
    fi
}

check_tools() {
    local t missing=""
    for t in tar sha256sum; do
        command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
    done
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || missing="$missing curl|wget"
    if [ -z "$missing" ]; then
        pass "tools for fetching images: tar, sha256sum, curl/wget"
    else
        fail "missing tools:$missing" "sudo apt install$missing"
    fi
}

echo "minibox environment check"
check_not_root
check_kernel
check_go
check_cgroup_v2
check_userns
check_overlayfs
check_subids
check_tools

echo
echo "Result: $fails failure(s), $warns warning(s)"
[ "$fails" -eq 0 ]
