#!/usr/bin/env bash
set -u
if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0 URL"
  echo "Example: $0 http://192.0.2.10"
  echo 'Checks a short list of HTTP paths on the supplied origin.'
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
