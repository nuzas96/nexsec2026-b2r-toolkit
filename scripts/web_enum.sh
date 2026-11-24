#!/usr/bin/env bash
set -u
if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0 URL"
  echo "Example: $0 http://192.0.2.10"
  echo 'Checks a short list of HTTP paths on the supplied origin.'
  echo 'This is NOT full directory enumeration or virtual-host discovery.'
  echo
  echo 'Manual follow-up on an authorized target (examples):'
  echo '  curl -sS http://AUTHORIZED_IP/ -o index.html'
  echo '  grep -Ein '\''href=|src=|action=|mailto:|@|<!--|TODO|login'\'' index.html | head -n 80'
  echo '  grep -Eoi '\''[A-Za-z0-9.-]+\.thm'\'' index.html | sort -u  # TryHackMe only'
  echo '  curl -sS -i -H "Host: DISCOVERED_HOSTNAME" http://AUTHORIZED_IP/ | head -n 45'
  echo '  Compare the default response with the Host-header response.'
  echo '  Never test discovered names outside the assigned scope.'
  echo '  Full workflow: docs/WEB_MANUAL_WORKFLOW.md'
  exit 0
fi
if (($# != 1)) || [[ -z ${1:-} ]]; then
  echo "Usage: $0 URL (try --help)" >&2
  exit 2
fi
for dependency in curl date sed; do
  command -v "$dependency" >/dev/null || { echo "Missing dependency: $dependency" >&2; exit 2; }
done
url=${1%/}; printf 'Timestamp: '; date -Is
for path in / /robots.txt /server-status /uploads/ /icons/; do
  printf '\n== %s ==\n' "$url$path"
  curl -sS --connect-timeout 3 --max-time 8 -o /dev/null -w 'HTTP %{http_code} bytes=%{size_download} type=%{content_type}\n' "$url$path" || echo 'request failed'
done
curl -sSI --connect-timeout 3 --max-time 8 "$url/" | sed -n '1,12p'
