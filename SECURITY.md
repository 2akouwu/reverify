# Security policy

## Supported version

Security fixes target the latest release.

## Acceptable use

Reverify is a reverse-engineering and binary-analysis toolkit intended for **authorized**
work: malware analysis, CTF, interoperability and compatibility research, vulnerability
research, and understanding software you own or have explicit permission to analyze.

Do not use it to:

- access, modify, or exfiltrate data from systems or accounts you are not authorized to test;
- circumvent licensing, activation, or copy protection on software you do not own or are not
  licensed to modify;
- develop or deploy malware, spyware, or credential/data-theft tooling against third parties;
- or conduct any activity that is illegal in your jurisdiction.

You are responsible for holding authorization for the artifacts and targets you analyze.

## Reporting a vulnerability

Report security issues in Reverify itself (path handling, code execution, sensitive-data
exposure) via a private GitHub security advisory:
<https://github.com/2akouwu/reverify/security/advisories/new>

Include the affected version/commit, a minimal reproduction that contains no real credentials
or private data, and the observed versus expected behavior.
