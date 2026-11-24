#!/usr/bin/env bash
set -u

usage() {
  cat <<EOF
Usage: $0 [--host HOSTNAME] URL
Examples:
  $0 http://192.0.2.10
  $0 --host lab.example.test http://192.0.2.10

Checks five fixed paths and root HTTP headers, without following redirects.
--host: send an HTTP Host header for an already-discovered, in-scope hostname.
This does NOT automatically discover hostnames or brute-force directories.
For HTTPS, a Host header alone does not set TLS SNI; use curl --resolve
when you need hostname-aware TLS and have authorized target details.

Manual follow-up:
  curl -sS http://AUTHORIZED_IP/ -o index.html
  grep -Ein 'href=|src=|action=|mailto:|@|<!--|TODO|login' index.html | head -n 80
  grep -Eoi '[A-Za-z0-9.-]+\\.thm' index.html | sort -u  # TryHackMe only
  $0 --host DISCOVERED_HOSTNAME http://AUTHORIZED_IP
  Full guide: docs/WEB_MANUAL_WORKFLOW.md
  ffuf/gobuster guide: cheatsheets/directory-enumeration.md
EOF
}

if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  usage
  exit 0
fi

host=''
url=''
while (($# > 0)); do
  case "$1" in
    --host)
      if (($# < 2)); then
        echo 'Missing value for --host' >&2
        exit 2
      fi
      host=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n $url ]]; then
        echo 'Only one URL may be supplied' >&2
        usage >&2
        exit 2
      fi
      url=$1
      shift
      ;;
  esac
done

if [[ -z $url || ( $url != http://* && $url != https://* ) ]]; then
  echo 'Supply a complete http:// or https:// URL' >&2
  usage >&2
  exit 2
fi
if [[ -n $host && ! $host =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ ]]; then
  echo 'Invalid --host hostname (letters, digits, dots and hyphens only)' >&2
  exit 2
fi

for dependency in curl date sed; do
  command -v "$dependency" >/dev/null || {
    echo "Missing dependency: $dependency" >&2
    exit 2
  }
done

headers=()
if [[ -n $host ]]; then
  headers=(-H "Host: $host")
fi
url=${url%/}
printf 'Timestamp: '
date -Is
printf 'URL: %s\n' "$url"
if [[ -n $host ]]; then
  printf 'HTTP Host header: %s\n' "$host"
fi

for path in / /robots.txt /server-status /uploads/ /icons/; do
  printf '\n== %s ==\n' "$url$path"
  curl -sS --connect-timeout 3 --max-time 8 "${headers[@]}" \
    -o /dev/null -w 'HTTP %{http_code} bytes=%{size_download} type=%{content_type}\n' \
    "$url$path" || echo 'request failed'
done
curl -sSI --connect-timeout 3 --max-time 8 "${headers[@]}" "$url/" | sed -n '1,12p'
