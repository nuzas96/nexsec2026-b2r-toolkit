#!/usr/bin/env bash
set -u

usage() {
  cat <<EOF
Usage: $0 [--full] TARGET
Examples:
  $0 192.0.2.10
  $0 --full 192.0.2.10

Default: bounded top-100 TCP service scan (60s host timeout).
--full: optional all 65535 TCP port scan (300s host timeout).
Both modes perform a best-effort NFS export query when showmount is installed.
Use only on an explicitly authorized target. A timeout means incomplete coverage.
EOF
}

if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  usage
  exit 0
fi

mode=quick
if (($# == 2)) && [[ $1 == --full ]]; then
  mode=full
  target=$2
elif (($# == 1)) && [[ -n $1 && $1 != -* ]]; then
  target=$1
else
  usage >&2
  exit 2
fi
if [[ -z $target || $target == -* ]]; then
  echo "Invalid target; supply one authorized IP or hostname" >&2
  exit 2
fi

for dependency in nmap date timeout; do
  command -v "$dependency" >/dev/null || {
    echo "Missing dependency: $dependency" >&2
    exit 2
  }
done

printf 'Timestamp: '
date -Is
if [[ $mode == full ]]; then
  echo 'Mode: FULL TCP (all 65535 ports; at most 300s per host; may not complete)'
  scan_options=(-p- --host-timeout 300s)
else
  echo 'Mode: QUICK TCP (top 100 ports; at most 60s per host)'
  scan_options=(--top-ports 100 --host-timeout 60s)
fi

nmap -n -Pn -sT -sV --version-light --max-retries 1 "${scan_options[@]}" "$target"
scan_status=$?

printf '\n== NFS exports (best effort) ==\n'
if command -v showmount >/dev/null; then
  nfs_result=$(timeout 5 showmount -e "$target" 2>&1)
  nfs_status=$?
  if ((nfs_status == 0)); then
    printf '%s\n' "$nfs_result"
  else
    printf 'NFS export query inconclusive (exit %s): RPC failed, unavailable or timed out.\n' "$nfs_status"
    [[ -n $nfs_result ]] && printf '%s\n' "$nfs_result"
    echo 'This does not establish whether an NFS service exists.'
  fi
else
  echo 'showmount unavailable; NFS query skipped (not proof NFS is absent)'
fi

if ((scan_status != 0)); then
  printf 'Nmap exited with status %s; review scan output for incomplete coverage.\n' "$scan_status" >&2
fi
exit "$scan_status"
