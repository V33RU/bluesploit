# Security Policy

BlueSploit is an offensive-security framework. This policy covers vulnerabilities **in BlueSploit itself** — not in the third-party Bluetooth stacks it tests.

## Supported Versions

Only the latest minor release receives security fixes. Older versions are unsupported.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security bugs.**

Please report privately through one of:

1. **GitHub Security Advisories** (preferred) — https://github.com/V33RU/bluesploit/security/advisories/new
2. **Email** — `Mr-IoT@mr-iot.dev` with subject `[BlueSploit Security]`

Include in your report:

- Affected version (`bluesploit --version` or commit hash)
- OS / Python version
- Steps to reproduce
- Impact assessment (RCE, privilege escalation, info disclosure, etc.)
- A proof-of-concept if you have one
- Whether you intend to publish, and your preferred timeline

## What to expect

| Stage | Target SLA |
| --- | --- |
| Initial acknowledgement | within **72 hours** |
| Triage + severity assessment | within **7 days** |
| Fix or mitigation in `main` | within **30 days** for high/critical |
| Public advisory + credit | after fix is released |

If a report is **declined** (e.g. duplicate, out of scope, or working as intended), you'll get a written explanation. You're welcome to push back if you disagree.

## Scope

**In scope** (please report):

- Code-execution, path-traversal, or injection bugs in the framework or its modules
- Credential / key-material leakage by the framework itself
- Supply-chain issues (malicious dependency, typo-squat) we should pin or replace

**Out of scope** (do not report here):

- Vulnerabilities in target Bluetooth stacks (BlueZ, Fluoride, Windows BT, etc.) — report those to the respective vendors.
- The fact that an exploit module successfully exploits a public CVE — that is the intended behavior.
- Issues requiring an attacker to already have local root on the user's machine.

## Disclosure

We follow **coordinated disclosure**. Once a fix ships, we publish a GitHub Security Advisory crediting the reporter (unless you'd rather stay anonymous).

## Safe-harbor

Good-faith security research against BlueSploit's own code is welcomed and will not result in legal action from the maintainers. This safe-harbor does **not** extend to using BlueSploit against third-party devices without authorization — see [Legal Disclaimer](docs/legal-disclaimer.md).
