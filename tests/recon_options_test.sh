#!/usr/bin/env bash
# Offline regression test: fake network tools prevent outbound requests.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
export MOCK_CALLS="$tmp/calls.txt"
: > "$MOCK_CALLS"

cat > "$tmp/bin/nmap" <<'MOCK'
#!/usr/bin/env bash
printf 'NMAP' >> "$MOCK_CALLS"
printf ' <%s>' "$@" >> "$MOCK_CALLS"
printf '\n' >> "$MOCK_CALLS"
echo 'Mock Nmap scan complete'
MOCK
cat > "$tmp/bin/showmount" <<'MOCK'
#!/usr/bin/env bash
echo 'clnt_create: RPC: Unable to receive'
exit 1
MOCK
cat > "$tmp/bin/curl" <<'MOCK'
#!/usr/bin/env bash
printf 'CURL' >> "$MOCK_CALLS"
printf ' <%s>' "$@" >> "$MOCK_CALLS"
printf '\n' >> "$MOCK_CALLS"
echo 'HTTP 200 bytes=59 type=text/html'
MOCK
chmod +x "$tmp/bin/nmap" "$tmp/bin/showmount" "$tmp/bin/curl"
export PATH="$tmp/bin:$PATH"

bash -n "$project_dir/scripts/network_enum.sh"
bash -n "$project_dir/scripts/web_enum.sh"
bash "$project_dir/scripts/network_enum.sh" --help | grep -Fq -- '--full'
bash "$project_dir/scripts/web_enum.sh" --help | grep -Fq -- '--host'

quick=$(bash "$project_dir/scripts/network_enum.sh" 192.0.2.10)
printf '%s\n' "$quick" | grep -Fq 'NFS export query inconclusive'
grep -Fq '<--top-ports> <100>' "$MOCK_CALLS"
grep -Fq '<--host-timeout> <60s>' "$MOCK_CALLS"

: > "$MOCK_CALLS"
bash "$project_dir/scripts/network_enum.sh" --full 192.0.2.10 >/dev/null
grep -Fq '<-p->' "$MOCK_CALLS"
grep -Fq '<--host-timeout> <300s>' "$MOCK_CALLS"
if grep -Fq '<--top-ports>' "$MOCK_CALLS"; then
  echo 'FAIL: --full must not use top-100 scan' >&2
  exit 1
fi

: > "$MOCK_CALLS"
web=$(bash "$project_dir/scripts/web_enum.sh" --host lab.example.test http://192.0.2.10)
printf '%s\n' "$web" | grep -Fq 'HTTP Host header: lab.example.test'
grep -Fq '<Host: lab.example.test>' "$MOCK_CALLS"
[[ $(grep -c '^CURL' "$MOCK_CALLS") -eq 6 ]] || {
  echo 'FAIL: web_enum should issue 5 path checks and one HEAD request' >&2
  exit 1
}

: > "$MOCK_CALLS"
bash "$project_dir/scripts/web_enum.sh" http://192.0.2.10 >/dev/null
if grep -Fq '<Host:' "$MOCK_CALLS"; then
  echo 'FAIL: default scan must not inject a custom Host header' >&2
  exit 1
fi

if bash "$project_dir/scripts/web_enum.sh" --host '../invalid' http://192.0.2.10 >/dev/null 2>&1; then
  echo 'FAIL: invalid Host accepted' >&2
  exit 1
fi
if bash "$project_dir/scripts/network_enum.sh" --full >/dev/null 2>&1; then
  echo 'FAIL: --full without target accepted' >&2
  exit 1
fi

echo 'PASS: recon options, compatibility and NFS messaging (offline mocks)'
