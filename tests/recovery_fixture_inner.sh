#!/usr/bin/env bash
set -euo pipefail
umask 022
kind=${1:?fixture kind required}

mkdir -p /etc/ssh /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
  /etc/cron.monthly /etc/systemd/system /etc/init.d /home/alice/.ssh \
  /var/spool/cron/crontabs /usr/local/bin /opt
cat > /etc/passwd <<'EOF'
root:x:0:0:root:/root:/bin/bash
alice:x:1001:1001:Alice:/home/alice:/bin/bash
EOF
cat > /etc/group <<'EOF'
root:x:0:
sudo:x:27:
EOF
if [[ $kind != missing-config ]]; then : > /etc/ssh/sshd_config; fi
: > /etc/crontab

if [[ $kind == positive || $kind == persistence-positive || $kind == process-positive ]]; then
  printf '%s\n' 'shadow:x:0:0:Unexpected:/root:/bin/bash' >> /etc/passwd
  printf '%s\n' 'sudo:x:27:alice' > /etc/group
  printf '%s\n' 'PermitRootLogin yes' 'PasswordAuthentication yes' > /etc/ssh/sshd_config
  printf '%s\n' 'ssh-ed25519 AAAATEST benign-fixture' > /home/alice/.ssh/authorized_keys
  chmod 666 /home/alice/.ssh/authorized_keys
  printf '%s\n' 'PATH=/tmp:/usr/bin' '@reboot root /tmp/maint.sh' > /etc/crontab
  printf '%s\n' '* * * * * root /tmp/maint.sh' > /etc/cron.d/odd-job
  chmod 666 /etc/cron.d/odd-job
  printf '%s\n' '@reboot /tmp/maint.sh' > /var/spool/cron/crontabs/alice
  chmod 600 /var/spool/cron/crontabs/alice
  printf '%s\n' '#!/bin/sh' 'exit 0' > /tmp/maint.sh
  chmod 777 /tmp/maint.sh
  printf '%s\n' '[Service]' 'ExecStart=/bin/true' > /etc/systemd/system/odd.service
  chmod 666 /etc/systemd/system/odd.service
  printf '%s\n' '#!/bin/sh' 'exit 0' > /etc/init.d/odd-startup
  chmod 777 /etc/init.d/odd-startup
  cp /usr/bin/id /tmp/odd-suid
  chmod 4755 /tmp/odd-suid
fi

if [[ $kind == benign ]]; then
  printf '%s\n' 'ssh-ed25519 AAAATEST approved-fixture' > /home/alice/.ssh/authorized_keys
  chmod 600 /home/alice/.ssh/authorized_keys
  printf '%s\n' '[Service]' 'ExecStart=/bin/true' > /etc/systemd/system/local-tool.service
  chmod 644 /etc/systemd/system/local-tool.service
  printf '%s\n' 'GROUND_TRUTH|authorized_key|approved fixture key, mode=600' 'GROUND_TRUTH|systemd|approved local unit, mode=644'
fi

if [[ $kind == process-positive ]]; then
  cp /usr/bin/sleep /tmp/odd-process
  chmod 777 /tmp/odd-process
  /tmp/odd-process 30 &
  process_pid=$!
  process_identity=$(ps -p "$process_pid" -o euid=,comm=)
  process_mode=$(stat -c '%a' /tmp/odd-process)
  [[ $process_identity == *odd-process* && $process_identity =~ ^[[:space:]]*0[[:space:]] && $process_mode == 777 ]]
  printf 'GROUND_TRUTH|process|euid=0|mode=%s|path=/tmp/odd-process|pid=%s\n' "$process_mode" "$process_pid"
fi

if [[ $kind == firewall-positive || $kind == firewall-negative ]]; then
  mkdir -p /tmp/testbin
  cat > /tmp/testbin/nft <<'EOF'
#!/usr/bin/bash
if [[ ${FIXTURE_FIREWALL:-drop} == accept ]]; then
  printf '%s\n' 'table inet filter {' ' chain input {' '  type filter hook input priority filter; policy accept;' ' }' '}'
else
  printf '%s\n' 'table inet filter {' ' chain input {' '  type filter hook input priority filter; policy drop;' ' }' '}'
fi
EOF
  chmod 755 /tmp/testbin/nft
  if [[ $kind == firewall-positive ]]; then
    printf '%s\n' 'GROUND_TRUTH|firewall|backend=nft|default_policy=accept'
    FIXTURE_FIREWALL=accept PATH=/tmp/testbin:/usr/bin:/bin /usr/bin/bash /tmp/toolkit/recovery_audit.sh
  else
    printf '%s\n' 'GROUND_TRUTH|firewall|backend=nft|default_policy=drop'
    PATH=/tmp/testbin:/usr/bin:/bin /usr/bin/bash /tmp/toolkit/recovery_audit.sh
  fi
  exit $?
fi

if [[ $kind == persistence-positive || $kind == persistence-negative ]]; then
  exec /tmp/toolkit/persistence_check.sh
fi
exec /tmp/toolkit/recovery_audit.sh
