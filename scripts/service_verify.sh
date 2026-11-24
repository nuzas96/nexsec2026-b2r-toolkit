#!/usr/bin/env bash
set -u
if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0 BASELINE_FILE [CURRENT_FILE]"
  echo "Example: $0 before.txt after.txt"
  echo 'With CURRENT_FILE omitted, captures current listeners and service state for comparison.'
  exit 0
fi
if (($# < 1 || $# > 2)); then echo "Usage: $0 BASELINE_FILE [CURRENT_FILE] (try --help)" >&2; exit 2; fi
missing=()
for dependency in grep diff sed sort date mktemp timeout awk; do
  command -v "$dependency" >/dev/null 2>&1 || missing+=("$dependency")
done
if ((${#missing[@]})); then
  printf 'Missing required command(s): %s\n' "${missing[*]}" >&2
  exit 2
fi
base=$1; current=${2:-}
if [[ ! -r $base ]]; then echo "Cannot read baseline: $base" >&2; exit 2; fi
if [[ ! -s $base ]]; then echo "Baseline is empty: $base" >&2; exit 2; fi
if [[ -z $current ]]; then current=$(mktemp); trap 'rm -f "$current"' EXIT
  if grep -qx 'FORMAT|NEXSEC-B2R-BASELINE-v1' "$base"; then
    if grep -q '^SERVICE|' "$base"; then
      if command -v systemctl >/dev/null && timeout 5 systemctl show-environment >/dev/null 2>&1; then
        timeout 8 systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null \
          | awk '{print "SERVICE|" $1 "|" $3 "|" $4}' >>"$current" || :
      else
        echo 'SERVICE|unavailable|service manager differs from baseline|unknown' >>"$current"
      fi
    fi
    if command -v ss >/dev/null; then
      timeout 5 ss -lntup 2>/dev/null | awk 'NR > 1 {print "LISTENER|" $1 "|" $2 "|" $5 "|" $6}' >>"$current" || :
    fi
    if grep -q '^INIT_SCRIPT|' "$base"; then
      timeout 8 find /etc/init.d -maxdepth 1 -type f -printf 'INIT_SCRIPT|%f|%m|%u:%g\n' 2>/dev/null >>"$current" || :
    fi
  else
    {
      if command -v ss >/dev/null; then timeout 5 ss -lntup 2>&1 || :; fi
      if command -v systemctl >/dev/null; then
        timeout 8 systemctl --no-pager --type=service --state=running 2>&1 || :
      elif command -v service >/dev/null; then
        timeout 8 service --status-all 2>&1 || :
      else
        echo 'No supported service manager command found'
      fi
    } | sed -E '/^Timestamp:/d; s/[[:space:]]+$//' | sort >"$current"
  fi
fi
if [[ ! -r $current ]]; then echo "Cannot read current snapshot: $current" >&2; exit 2; fi
if [[ ! -s $current ]]; then echo "Current snapshot is empty: $current" >&2; exit 2; fi
for snapshot in "$base" "$current"; do
  if grep -qx 'FORMAT|NEXSEC-B2R-BASELINE-v1' "$snapshot" && ! grep -Eq '^(SERVICE|INIT_SCRIPT|LISTENER)\|' "$snapshot"; then
    echo "No comparable service or listener records in snapshot: $snapshot" >&2
    exit 2
  fi
done
printf 'Comparing normalized service snapshots\n'
printf 'Comparison time: '; date -Is
normalize_snapshot() {
  local path=$1
  if grep -qx 'FORMAT|NEXSEC-B2R-BASELINE-v1' "$path"; then
    awk -F'|' '$1 == "SERVICE" || $1 == "LISTENER" || $1 == "INIT_SCRIPT"' "$path" | sort
  else
    sed -E '/^Timestamp:/d; s/[[:space:]]+$//' "$path" | sort
  fi
}
if diff -u <(normalize_snapshot "$base") <(normalize_snapshot "$current"); then
  echo 'PASS: service snapshots are identical'
else
  rc=$?
  if ((rc == 1)); then
    echo 'DIFFERENCE: service snapshots changed'
    exit 1
  fi
  exit "$rc"
fi
