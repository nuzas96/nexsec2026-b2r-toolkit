#!/usr/bin/env bash
set -u -o pipefail

if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0"
  echo "Example: $0 > recovery-audit.txt"
  echo 'Produces a bounded, read-only pipe-delimited indicator report. No indicator alone confirms compromise.'
  exit 0
fi
if (($# != 0)); then echo "Usage: $0 (try --help)" >&2; exit 2; fi
missing=()
for dependency in awk find stat timeout date hostname tr head wc; do
  command -v "$dependency" >/dev/null 2>&1 || missing+=("$dependency")
done
if ((${#missing[@]})); then
  printf 'Missing required command(s): %s\n' "${missing[*]}" >&2
  exit 2
fi

clean() { printf '%s' "$1" | tr '\n\r|' '   '; }
row() { printf '%s\n' "$*"; }
finding() {
  row "FINDING|$1|$2|$3|$(clean "$4")|$(clean "$5")"
}
mode_is_group_or_other_writable() {
  local mode=${1#0}
  [[ $mode =~ ^[0-7]+$ ]] || return 1
  (( (8#$mode & 0022) != 0 ))
}

row 'FORMAT|NEXSEC-RECOVERY-AUDIT-v1'
row "CAPTURED_AT|$(date -u +%Y-%m-%dT%H:%M:%SZ)"
row "HOST|$(clean "$(hostname 2>/dev/null || echo unavailable)")"
row 'ASSESSMENT|Indicators require validation against an approved inventory and owner. This report does not assert compromise.'

printf 'SECTION|accounts_and_privileges\n'
if [[ -r /etc/passwd ]]; then
  while IFS=: read -r name _ uid gid _ home shell; do
    [[ $uid =~ ^[0-9]+$ ]] || continue
    if [[ $uid == 0 && $name != root ]]; then
      finding HIGH account unexpected_uid0 "$name uid=$uid gid=$gid home=$home shell=$shell" 'Confirm account ownership and approved break-glass use; UID 0 alone does not prove compromise.'
    elif ((uid >= 1000)) && [[ $name != nobody ]]; then
      row "OBSERVATION|account|uid=$uid|name=$name|home=$home"
    fi
  done < /etc/passwd
else
  row 'CHECK|accounts|unavailable|/etc/passwd unreadable or missing'
fi
if [[ -r /etc/group ]]; then
  awk -F: '$1 == "sudo" || $1 == "wheel" || $1 == "admin" || $1 == "docker" || $1 == "lxd" {print $1 "|" $3 "|" $4}' /etc/group \
    | while IFS='|' read -r group gid members; do
        [[ -n $group ]] || continue
        row "OBSERVATION|admin_group|$group|gid=$gid|members=$(clean "$members")"
        [[ -n $members ]] && finding REVIEW admin_group membership "$group members=$(clean "$members")" 'Compare administrative memberships with the approved access inventory; do not remove users based on name alone.'
      done
fi
if command -v sudo >/dev/null; then
  sudo_output=$(timeout 5 sudo -l </dev/null 2>/dev/null || true)
  sudo_count=$(printf '%s\n' "$sudo_output" | awk '/\([^)]*\)[[:space:]]/ {count++} END {print count+0}')
  if ((sudo_count > 0)); then
    finding REVIEW sudo sudo_list_entries "entries=$sudo_count for current account" 'Review exact grants with the account owner; the audit intentionally does not copy command arguments.'
  else
    row 'CHECK|sudo|partial|Listing unavailable, no grants shown, or command unsupported'
  fi
else
  row 'CHECK|sudo|unavailable|sudo command not installed'
fi
for sudo_file in /etc/sudoers /etc/sudoers.d/*; do
  [[ -f $sudo_file ]] || continue
  sudo_meta=$(stat -c '%a|%U:%G' "$sudo_file" 2>/dev/null || echo 'unknown|unknown')
  sudo_mode=${sudo_meta%%|*}; sudo_owner=${sudo_meta#*|}
  row "OBSERVATION|sudo_policy_metadata|$sudo_file|mode=$sudo_mode|owner=$sudo_owner"
  if mode_is_group_or_other_writable "$sudo_mode" || [[ $sudo_owner != root:* ]]; then
    finding HIGH sudo writable_sudo_policy "$sudo_file mode=$sudo_mode owner=$sudo_owner" 'Validate the sudoers syntax and approved policy owner before changing its permissions.'
  fi
done

printf 'SECTION|ssh\n'
ssh_config=/etc/ssh/sshd_config
if [[ -r $ssh_config ]]; then
  while IFS='|' read -r key value; do
    [[ -n $key ]] || continue
    case "$key:$value" in
      PermitRootLogin:yes|PermitRootLogin:without-password|PasswordAuthentication:yes|PermitEmptyPasswords:yes|AllowTcpForwarding:yes|X11Forwarding:yes)
        finding REVIEW ssh ssh_setting "$ssh_config $key=$value" 'Compare against the approved remote-access baseline and service requirements.' ;;
      *) row "OBSERVATION|ssh_setting|$key=$value" ;;
    esac
  done < <(awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*#/ || NF<2 {next} {key=tolower($1); if (key=="permitrootlogin" || key=="passwordauthentication" || key=="permitemptypasswords" || key=="allowtcpforwarding" || key=="x11forwarding" || key=="pubkeyauthentication") print $1 "|" $2}' "$ssh_config")
else
  row "CHECK|ssh|unavailable|$ssh_config unreadable or missing"
fi
for base in /root /home/*; do
  [[ -d $base ]] || continue
  if [[ ! -r $base || ! -x $base ]]; then
    row "CHECK|authorized_keys|partial|cannot traverse $base with current permissions"
    continue
  fi
  if ! timeout 8 find "$base" -maxdepth 6 -type f -path '*/.ssh/authorized_keys' -printf '%m|%u:%g|%p|%s bytes\n' 2>/dev/null \
    | while IFS='|' read -r mode owner path size; do
        row "OBSERVATION|authorized_keys_metadata|$path|mode=$mode|owner=$owner|$size"
        finding REVIEW authorized_key key_file_present "$path mode=$mode owner=$owner $size" 'Validate key ownership and fingerprints through approved records; key contents are intentionally omitted.'
        if mode_is_group_or_other_writable "$mode"; then
          finding HIGH authorized_key writable_authorized_keys "$path mode=$mode owner=$owner" 'Confirm every key with the account owner and access records; file permissions are not proof that a key was used.'
        fi
      done; then
    row "CHECK|authorized_keys|partial|search timed out or access changed under $base"
  fi
done

printf 'SECTION|scheduled_tasks\n'
for cron_file in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
  [[ -f $cron_file && -r $cron_file ]] || continue
  metadata=$(stat -c '%a|%U:%G' "$cron_file" 2>/dev/null || echo 'unknown|unknown')
  mode=${metadata%%|*}; owner=${metadata#*|}
  if mode_is_group_or_other_writable "$mode" || [[ $owner != root:* ]]; then
    finding HIGH cron writable_cron_file "$cron_file mode=$mode owner=$owner" 'Confirm the scheduler consumes this file and the write access is unintended.'
  fi
  line_number=0
  while IFS= read -r line; do
    ((line_number += 1))
    [[ -z $line || $line == \#* || $line == SHELL=* || $line == MAILTO=* ]] && continue
    if [[ $line == PATH=* ]]; then
      path_value=${line#PATH=}
      if [[ $path_value =~ (^|:)(/var/tmp|/tmp|/dev/shm|/home)(/|:|$) ]]; then
        finding REVIEW cron cron_path_contains_writable_area "$cron_file:$line_number PATH includes a writable-area candidate" 'Verify effective directory permissions and which scheduled jobs inherit this PATH.'
      fi
      continue
    fi
    read -r -a fields <<< "$line"
    if [[ $cron_file == /var/spool/cron/crontabs/* ]]; then
      job_user=${cron_file##*/}
      if [[ ${fields[0]:-} == @* ]]; then
        (( ${#fields[@]} >= 2 )) || continue
        command=${fields[1]}
      else
        (( ${#fields[@]} >= 6 )) || continue
        command=${fields[5]}
      fi
    elif [[ ${fields[0]:-} == @* ]]; then
      (( ${#fields[@]} >= 3 )) || continue
      job_user=${fields[1]}
      command=${fields[2]}
    else
      (( ${#fields[@]} >= 7 )) || continue
      job_user=${fields[5]}
      command=${fields[6]}
    fi
    command=${command%%[[:space:]]*}
    command_name=${command##*/}
    indicator='scheduled_command_review'
    case "$command" in
      /tmp/*|/var/tmp/*|/dev/shm/*|/home/*) indicator='scheduled_command_in_writable_area' ;;
    esac
    case "$command_name" in
      curl|wget|nc|ncat|netcat|bash|sh|python*|perl*|php*|ruby*) indicator='scheduled_command_uses_transfer_or_interpreter' ;;
    esac
    if [[ $indicator != scheduled_command_review ]]; then
      finding REVIEW cron "$indicator" "$cron_file:$line_number user=$job_user executable=$command" 'Review the full command locally without copying possible secrets into this report.'
    fi
    if [[ $command == /* && -f $command ]]; then
      command_meta=$(stat -c '%a|%U:%G' "$command" 2>/dev/null || echo 'unknown|unknown')
      command_mode=${command_meta%%|*}; command_owner=${command_meta#*|}
      if mode_is_group_or_other_writable "$command_mode" || [[ $command_owner != root:* ]]; then
        finding HIGH cron writable_scheduled_executable "$cron_file:$line_number executable=$command mode=$command_mode owner=$command_owner" 'Confirm the job runs with elevated privileges and the ownership exception is unintended.'
      fi
    fi
  done < "$cron_file"
done
for directory in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  [[ -d $directory ]] || continue
  if [[ ! -r $directory || ! -x $directory ]]; then
    row "CHECK|cron|partial|cannot inspect $directory with current permissions"
    continue
  fi
  mode=$(stat -c '%a' "$directory" 2>/dev/null || echo unknown)
  if mode_is_group_or_other_writable "$mode"; then
    finding HIGH cron writable_cron_directory "$directory mode=$mode" 'Confirm scheduler scope and correct permissions only after validating the host baseline.'
  fi
done

printf 'SECTION|services_and_startup\n'
for directory in /etc/systemd/system /usr/local/lib/systemd/system; do
  [[ -d $directory ]] || continue
  if [[ ! -r $directory || ! -x $directory ]]; then
    row "CHECK|systemd|partial|cannot inspect $directory with current permissions"
    continue
  fi
  if ! timeout 8 find "$directory" -maxdepth 4 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) -printf '%m|%u:%g|%p\n' 2>/dev/null \
    | while IFS='|' read -r mode owner path; do
        finding REVIEW systemd unit_file "$path mode=$mode owner=$owner" 'Compare non-vendor unit files with the approved service inventory; a custom unit is not automatically malicious.'
        if mode_is_group_or_other_writable "$mode" || [[ $owner != root:* ]]; then
          finding HIGH systemd writable_unit "$path mode=$mode owner=$owner" 'Confirm unit ownership and dependencies before changing it; preserve service availability.'
        fi
      done; then
    row "CHECK|systemd|partial|search timed out or access changed under $directory"
  fi
done
if [[ -d /etc/init.d ]]; then
  if ! timeout 8 find /etc/init.d -maxdepth 1 -type f \( -perm /022 -o ! -user root \) -printf '%m|%u:%g|%p\n' 2>/dev/null \
    | while IFS='|' read -r mode owner path; do
        finding HIGH sysv writable_startup_script "$path mode=$mode owner=$owner" 'Verify whether the script is called during startup and identify its service owner before remediation.'
      done; then
    row 'CHECK|sysv|partial|search timed out or access changed under /etc/init.d'
  fi
fi
for path in /etc/rc.local /etc/init.d/rc.local; do
  [[ -f $path ]] || continue
  mode=$(stat -c '%a' "$path" 2>/dev/null || echo unknown)
  owner=$(stat -c '%U:%G' "$path" 2>/dev/null || echo unknown)
  if mode_is_group_or_other_writable "$mode" || [[ $owner != root:* ]]; then
    finding HIGH startup writable_rc_local "$path mode=$mode owner=$owner" 'Confirm whether this host invokes the file at boot; do not edit or remove it during evidence collection.'
  fi
done

printf 'SECTION|writable_privileged_files\n'
for directory in /etc /usr/local/bin /usr/local/sbin /opt; do
  [[ -d $directory ]] || continue
  if ! timeout 8 find "$directory" -maxdepth 5 -type f -perm /022 -printf '%m|%u:%g|%p\n' 2>/dev/null \
    | while IFS='|' read -r mode owner path; do
        finding HIGH writable_file group_or_other_writable "$path mode=$mode owner=$owner" 'Confirm whether the file is security-sensitive and whether the write bits are required.'
      done; then
    row "CHECK|writable_files|partial|search timed out or access changed under $directory"
  fi
done

printf 'SECTION|suid_sgid\n'
for directory in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home /tmp /var/tmp; do
  [[ -d $directory ]] || continue
  if ! timeout 8 find "$directory" -maxdepth 5 -type f \( -perm -4000 -o -perm -2000 \) -printf '%m|%u:%g|%p\n' 2>/dev/null \
    | while IFS='|' read -r mode owner path; do
        case "$directory" in
          /bin|/sbin|/usr/bin|/usr/sbin)
            row "OBSERVATION|standard_privileged_binary|$path|mode=$mode|owner=$owner" ;;
          *) finding REVIEW suid_sgid nonstandard_privileged_binary "$path mode=$mode owner=$owner" 'Compare with package ownership and a known-good host baseline; privilege bits alone do not prove abuse.' ;;
        esac
      done; then
    row "CHECK|suid_sgid|partial|search timed out or access changed under $directory"
  fi
done

printf 'SECTION|process_ownership\n'
if command -v ps >/dev/null && command -v readlink >/dev/null; then
  process_count=0 process_access_gaps=0
  while read -r real_uid effective_uid pid command_name; do
    [[ $pid =~ ^[0-9]+$ ]] || continue
    ((process_count += 1))
    if ((process_count > 256)); then
      row 'CHECK|processes|partial|process listing capped at 256 entries'
      break
    fi
    row "OBSERVATION|process_identity|pid=$pid|uid=$real_uid|euid=$effective_uid|name=$(clean "$command_name")"
    executable=$(readlink "/proc/$pid/exe" 2>/dev/null) || { ((process_access_gaps += 1)); continue; }
    executable=${executable% (deleted)}
    process_meta=$(stat -Lc '%a|%U:%G' "/proc/$pid/exe" 2>/dev/null) || { ((process_access_gaps += 1)); continue; }
    process_mode=${process_meta%%|*}; process_owner=${process_meta#*|}
    row "OBSERVATION|process|pid=$pid|uid=$real_uid|euid=$effective_uid|name=$(clean "$command_name")|exe=$(clean "$executable")|mode=$process_mode|owner=$process_owner"
    if [[ $process_owner == UNKNOWN:UNKNOWN ]]; then ((process_access_gaps += 1)); fi
    if [[ $effective_uid == 0 ]]; then
      case "$executable" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*)
          finding REVIEW process privileged_process_from_nonstandard_path "pid=$pid euid=0 exe=$executable" 'Confirm process identity and executable provenance; a nonstandard path alone does not establish malicious activity.' ;;
      esac
      if mode_is_group_or_other_writable "$process_mode"; then
        finding HIGH process privileged_process_writable_executable "pid=$pid euid=0 exe=$executable mode=$process_mode owner=$process_owner" 'Preserve process and executable evidence, then verify package ownership and intended execution context.'
      elif [[ $process_owner != root:* && $process_owner != UNKNOWN:UNKNOWN ]]; then
        finding REVIEW process privileged_process_nonroot_owned_executable "pid=$pid euid=0 exe=$executable owner=$process_owner" 'Compare the executable owner with the approved service and package inventory.'
      fi
    fi
  done < <(timeout 5 ps -eo uid=,euid=,pid=,comm= --sort=pid 2>/dev/null | head -n 257)
  if ((process_access_gaps > 0)); then
    row "CHECK|processes|partial|executable metadata unavailable for $process_access_gaps process entries"
  fi
  if ((EUID != 0)); then row 'CHECK|processes|partial|process executable ownership may be hidden without elevated permissions'; fi
else
  row 'CHECK|processes|unavailable|ps or readlink not installed'
fi

printf 'SECTION|listeners_and_processes\n'
if command -v ss >/dev/null; then
  timeout 5 ss -lntup 2>/dev/null | awk 'NR > 1 {sub(/^[[:space:]]+/, ""); print "OBSERVATION|listener|" $0}'
  if ((EUID != 0)); then row 'CHECK|listeners|partial|process ownership may be hidden without elevated permissions'; fi
else
  row 'CHECK|listeners|unavailable|ss not installed'
fi

printf 'SECTION|firewall\n'
if command -v nft >/dev/null; then
  output=$(timeout 5 nft list ruleset 2>/dev/null | head -c 1048576)
  firewall_status=$?
  if ((firewall_status != 0)); then row "CHECK|firewall|partial|nft query exited with status $firewall_status or exceeded five seconds"; fi
  if [[ -n $output ]]; then
    rules=$(printf '%s\n' "$output" | wc -l)
    accept_chains=$(printf '%s\n' "$output" | awk '/type[[:space:]]+filter[[:space:]]+hook/ && /policy[[:space:]]+accept/ {count++} END {print count+0}')
    row "OBSERVATION|firewall|nft|rules=$rules|default_accept_chains=$accept_chains"
    if ((accept_chains > 0)); then
      finding REVIEW firewall default_accept_policy "backend=nft base_chains=$accept_chains" 'Compare the default policy with the approved network baseline; accept policy may be intentional for this host.'
    fi
  else
    row 'CHECK|firewall|nft|installed but ruleset unavailable or empty'
  fi
elif command -v iptables-save >/dev/null; then
  output=$(timeout 5 iptables-save 2>/dev/null | head -c 1048576)
  firewall_status=$?
  if ((firewall_status != 0)); then row "CHECK|firewall|partial|iptables query exited with status $firewall_status or exceeded five seconds"; fi
  if [[ -n $output ]]; then
    rules=$(printf '%s\n' "$output" | wc -l)
    accept_chains=$(printf '%s\n' "$output" | awk '/^:[^ ]+[[:space:]]+ACCEPT([[:space:]]|$)/ {count++} END {print count+0}')
    row "OBSERVATION|firewall|iptables|rules=$rules|default_accept_chains=$accept_chains"
    if ((accept_chains > 0)); then
      finding REVIEW firewall default_accept_policy "backend=iptables base_chains=$accept_chains" 'Compare default chain policies with the approved network baseline; accept policy may be intentional for this host.'
    fi
  else
    row 'CHECK|firewall|iptables|installed but ruleset unavailable or empty'
  fi
elif command -v ufw >/dev/null; then
  state=$(timeout 5 ufw status 2>/dev/null | awk -F': ' '/^Status:/ {print $2; exit}')
  row "OBSERVATION|firewall|ufw|status=${state:-unknown}"
else
  row 'CHECK|firewall|unavailable|no supported firewall query tool found'
fi

printf 'SECTION|persistence_indicators\n'
for path in /etc/xdg/autostart /root/.config/autostart /home/*/.config/autostart; do
  [[ -d $path ]] || continue
  if ! timeout 5 find "$path" -maxdepth 2 -type f -printf '%m|%u:%g|%p\n' 2>/dev/null \
    | while IFS='|' read -r mode owner file; do
        finding REVIEW persistence autostart_entry "$file mode=$mode owner=$owner" 'Confirm the entry with its desktop or service owner; an autostart file is not automatically unauthorized.'
      done; then
    row "CHECK|persistence|partial|search timed out or access changed under $path"
  fi
done
row 'ASSESSMENT|All findings are indicators for corroboration. No files were changed and no sensitive file contents were collected.'
