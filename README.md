# Privilege Escalation Playbooks

Concise operator guides for escalating privileges on modern Windows and Linux systems. These notes focus on workflows, checks, and command patterns you can reuse in labs or assessments, not one-off walkthroughs.

## Contents
- [Linux Privilege Escalation](privilege-escalation/linux-privilege-escalation.md) — manual and automated enumeration, credential discovery, writable jobs/paths, SUID/sudo, and kernel angles.
- [Windows Privilege Escalation](privilege-escalation/windows-privilege-escalation.md) — privilege model essentials, situational awareness, service/DLL path hijacking, scheduled tasks, and exploit pointers.

## How to Use
- Start with the enumeration sections to build context before attempting exploits.
- Copy commands selectively; adapt targets, IPs, and payloads to your environment.
- Combine manual checks with one or two automated tools, then validate high-value findings.
- Follow your engagement rules of engagement (RoE): obtain authorization, minimize noise, and clean up artifacts.


