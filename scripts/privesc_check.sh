#!/usr/bin/env bash
set -u
if (($# == 1)) && [[ $1 == -h || $1 == --help ]]; then
  echo "Usage: $0"
  echo "Example: $0"
  echo 'Read-only, time-bounded checks for local privilege escalation indicators.'
  exit 0
fi
if (($# != 0)); then echo "Usage: $0 (try --help)" >&2; exit 2; fi
missing=()
for dependency in date find timeout sed head ls stat grep dirname; do
  command -v "$dependency" >/dev/null 2>&1 || missing+=("$dependency")
done
if ((${#missing[@]})); then
  printf 'Missing required command(s): %s\n' "${missing[*]}" >&2
  exit 2
fi
printf 'Timestamp: '; date -Is
printf '== SUID/SGID files ==\n'
timeout 15 find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /opt -type f \( -perm -4000 -o -perm -2000 \) -printf '%m %u:%g %p\n' 2>/dev/null || echo 'search timed out or a search path was unavailable'

printf '== sudo privileges ==\n'
if command -v sudo >/dev/null; then
  timeout 6 sudo -l </dev/null 2>&1 || echo 'sudo listing unavailable, requires authentication, or timed out'
else
  echo 'sudo unavailable'
fi

printf '== file capabilities ==\n'
if command -v getcap >/dev/null; then
  timeout 15 getcap -r /bin /sbin /usr/bin /usr/sbin /usr/local/bin /opt /home 2>/dev/null || echo 'capability search timed out'
else
  echo 'getcap unavailable'
fi

printf '== cron and scheduled files ==\n'
cron_path=${PATH:-/usr/bin:/bin}
if [[ -r /etc/crontab ]]; then
  configured_path=$(sed -n 's/^PATH=//p' /etc/crontab | head -1)
  [[ -n $configured_path ]] && cron_path=$configured_path
fi
for path in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
  [[ -e $path ]] || continue
  ls -ld "$path" 2>&1
  if [[ -d $path ]]; then
    timeout 5 find "$path" -maxdepth 1 -type f -printf '%m %u:%g %p\n' 2>/dev/null || echo "listing timed out or permission denied: $path"
  fi
done
for cron_file in /etc/crontab /etc/cron.d/*; do
  [[ -f $cron_file && -r $cron_file ]] || continue
  while IFS= read -r line; do
    [[ -z $line || $line == \\#* || $line == PATH=* || $line == SHELL=* ]] && continue
    read -r -a fields <<< "$line"
    [[ ${#fields[@]} -ge 7 ]] || continue
    command=${fields[6]}
    command=${command%%[[:space:]]*}
    [[ -n $command ]] || continue
    if [[ $command == /* ]]; then
      [[ -f $command && -w $command ]] && printf 'writable scheduled executable: %s (from %s)\n' "$command" "$cron_file"
      continue
    fi
    old_ifs=$IFS
    IFS=:
    for directory in $cron_path; do
      if [[ -d $directory && -w $directory ]]; then
        case " ${reported_cron_path_dirs:-} " in
          *" $directory "*) ;;
          *) printf 'writable cron PATH directory: %s (from %s)\n' "$directory" "$cron_file"; reported_cron_path_dirs="${reported_cron_path_dirs:-} $directory" ;;
        esac
      fi
      candidate=${directory%/}/$command
      [[ -f $candidate && -w $candidate ]] && printf 'writable scheduled executable: %s (from %s)\n' "$candidate" "$cron_file"
    done
    IFS=$old_ifs
  done < "$cron_file"
done

printf '== writable privileged configuration and executables ==\n'
for path in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/init.d /usr/local/bin /usr/local/sbin /opt; do
  [[ -e $path ]] || continue
  timeout 8 find "$path" -maxdepth 3 -type f -writable -printf '%m %u:%g %p\n' 2>/dev/null || echo "writable-file search timed out or permission denied: $path"
done
for path in /etc/exports /etc/rc.local /etc/init.d/rc.local; do
  [[ -f $path && -w $path ]] && stat -c 'writable privileged file: %a %A %U:%G %n' "$path"
done

printf '== sensitive file metadata ==\n'
for path in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config; do
  [[ -e $path ]] && stat -c '%a %A %U:%G %n' "$path" 2>&1
done

printf '== PATH directory permissions ==\n'
old_ifs=$IFS
IFS=:
for path in $PATH; do
  [[ -d $path ]] || continue
  if [[ -w $path ]]; then printf 'writable PATH directory: %s\n' "$path"; fi
done
IFS=$old_ifs

printf '== SUID binaries with relative command references ==\n'
if command -v strings >/dev/null; then
  timeout 12 find /usr/local/bin /opt -maxdepth 4 -type f -perm -4000 -print 2>/dev/null | while IFS= read -r path; do
    strings "$path" 2>/dev/null | grep -E '(^|[[:space:];|&])(service|system|bash|sh)[[:space:]]' | head -5 | sed "s|^|$path: |"
    strings "$path" 2>/dev/null | grep -E '/[^[:space:]]+\.so([[:space:]]|$)' | while IFS= read -r library; do
      [[ -e $library ]] && continue
      parent=$(dirname "$library")
      while [[ ! -d $parent && $parent != / ]]; do parent=$(dirname "$parent"); done
      [[ -w $parent ]] && printf 'SUID binary references missing library under writable path: %s -> %s\n' "$path" "$library"
    done
  done
fi
