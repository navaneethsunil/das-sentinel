#!/bin/sh
# Per-run scanner sandbox entry (sec-15 / sec-18). Runs as PID 1's child inside
#   unshare --user --map-root-user --pid --fork --net --mount
# i.e. root ONLY within this run's private namespaces (uid 10001 outside). It
# builds the run's private filesystem + network view and then drops EVERY
# capability before exec'ing the scanner, so the tool itself can neither undo the
# mounts nor reconfigure the namespace. Mounts copied from the worker are locked
# by the kernel (a nested user namespace cannot unmount them to peek underneath).
#
# Contract (environment, set by app/workers/execution.py; all unset before exec):
#   DAS_SANDBOX_KEEP   ':'-separated dirs under /tmp this run owns (its workdir,
#                      its extracted source) — re-bound into the private /tmp so
#                      the tool sees ONLY its own scratch, never a sibling scan's.
#   DAS_SANDBOX_HOSTS  newline-separated "<ip> <name>" lines: the ONLY names the
#                      tool can resolve (the scope-vetted pinned target + declared
#                      online DBs). There is no DNS in the sandbox.
#   DAS_SANDBOX_NET    "<child-ip>/<prefix> <gateway-ip>" when the parent attaches
#                      a veth (network scanners); empty = no network at all.
set -eu

SANDBOX_PATH=/usr/sbin:/usr/bin:/sbin:/bin
TOOL_PATH="${PATH:-}"
export PATH="$SANDBOX_PATH"

# ── private /tmp ─────────────────────────────────────────────────────────────
# Stage this run's own dirs on a scratch tmpfs, hide the shared /tmp under a
# fresh one, then bind the staged dirs back at their original paths (the tool's
# argv already names them) so writes land in the real dirs the worker reads.
mount -t tmpfs -o nosuid,nodev,mode=0700 tmpfs /mnt
i=0
for d in $(printf '%s' "${DAS_SANDBOX_KEEP:-}" | tr ':' ' '); do
  mkdir "/mnt/$i" && mount --bind "$d" "/mnt/$i"
  i=$((i + 1))
done
mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs /tmp
i=0
for d in $(printf '%s' "${DAS_SANDBOX_KEEP:-}" | tr ':' ' '); do
  mkdir -p "$d" && mount --bind "/mnt/$i" "$d" && umount "/mnt/$i"
  i=$((i + 1))
done
umount /mnt

# ── name resolution: pinned hosts only, no DNS ───────────────────────────────
printf '127.0.0.1 localhost\n%s\n' "${DAS_SANDBOX_HOSTS:-}" > /tmp/.sandbox-hosts
: > /tmp/.sandbox-resolv
mount --bind /tmp/.sandbox-hosts /etc/hosts
mount --bind /tmp/.sandbox-resolv /etc/resolv.conf

# ── network: our end of the veth the parent attaches (or nothing) ────────────
ip link set lo up 2>/dev/null || true
if [ -n "${DAS_SANDBOX_NET:-}" ]; then
  set -- "$DAS_SANDBOX_NET" "$@"
  child_cidr=${1%% *}
  gateway=${1##* }
  shift
  n=0
  while ! ip link show eth0 >/dev/null 2>&1; do
    n=$((n + 1))
    if [ "$n" -gt 250 ]; then echo "sandbox: veth never attached" >&2; exit 97; fi
    sleep 0.02
  done
  ip addr add "$child_cidr" dev eth0
  ip link set eth0 up
  ip route add default via "$gateway"
fi

unset DAS_SANDBOX_KEEP DAS_SANDBOX_HOSTS DAS_SANDBOX_NET
export PATH="$TOOL_PATH"
# Drop everything: bounding set empty → no capability can ever be regained,
# even by root-in-namespace on execve. no-new-privs is already inherited.
exec setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- "$@"
