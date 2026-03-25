---
layout: default
title: Home
---

# Privilege Escalation Guide

A comprehensive reference for Linux and Windows privilege escalation techniques, tradecraft, and exploitation patterns. Designed for penetration testers and security researchers.

## Key Resources

- **[GTFOBins](https://gtfobins.org/)** - SUID/Capability binary exploitation reference
- **[Escabin](https://medtrigui.github.io/escabin/)** - Forked GTFOBins with detailed exploits
- **[SearchSploit](https://www.exploit-db.com/)** - Exploit database search

## Quick Navigation

<div class="cards">
  <div class="card">
    <h3>Linux Privilege Escalation</h3>
    <p>Comprehensive Linux enumeration, exploitation, and escalation techniques covering:</p>
    <ul>
      <li>Manual & automated enumeration</li>
      <li>Credential harvesting from user trails</li>
      <li>Writable file exploitation</li>
      <li>SUID/Capability abuse</li>
      <li>Sudo misconfigurations</li>
      <li>Kernel vulnerabilities</li>
    </ul>
    <p><a href="{{ '/docs/linux-privilege-escalation/' | relative_url }}">Read Guide →</a></p>
  </div>
  
  <div class="card">
    <h3>Windows Privilege Escalation</h3>
    <p>Systematic Windows enumeration and escalation patterns including:</p>
    <ul>
      <li>System information gathering</li>
      <li>Credential discovery and reuse</li>
      <li>Service & registry exploitation</li>
      <li>Token impersonation</li>
      <li>Kernel vulnerabilities</li>
    </ul>
    <p><a href="{{ '/docs/windows-privilege-escalation/' | relative_url }}">Read Guide →</a></p>
  </div>
</div>

## About

This guide emphasizes:

- **Repeatable tradecraft** - Techniques applicable across diverse environments
- **Recon-driven exploitation** - Thorough enumeration before advanced attacks
- **Generalized examples** - Reference patterns rather than lab-specific walkthroughs
- **External tools** - Always cross-reference with GTFOBins, Escabin, and SearchSploit

## Disclaimer

This material is for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal.
