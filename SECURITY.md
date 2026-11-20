# Security Policy

`device-checkup` is a security tool: it runs antivirus engines, downloads scanners, reads system settings, and hands untrusted file contents to an AI agent. Reports that help keep it safe are very welcome.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: [Report a vulnerability](https://github.com/rzrabbi/device-checkup-skill/security/advisories/new) (Security tab → "Report a vulnerability").

Please include:

- What the problem is and why it matters
- Steps to reproduce (OS, agent, Python version, and the command or prompt used)
- The impact you think it has
- A suggested fix, if you have one

This is a personal open source project maintained on a best-effort basis. I aim to acknowledge reports within 7 days and to agree on a disclosure date with you once a fix is ready. Reporters are credited in the advisory unless they prefer not to be.

## Supported versions

Only the latest version on the `main` branch is supported. Please reproduce issues against it before reporting.

## What counts as a vulnerability

In scope:

- **Unsafe downloads**: getting `clamav-setup` to install a file that was not verified against the official release checksum, or from an unexpected source. (Loki-RS is never downloaded by the skill; a way to make it download or run Loki automatically is in scope.)
- **Archive extraction**: path traversal, unsafe links, or other ways a downloaded archive can write outside its install folder.
- **Command injection**: file paths, task names, extension names, or other system data that end up executed by PowerShell or a shell in `scan.py`.
- **Agent manipulation (prompt injection)**: content on a scanned computer (file names, file contents, task names, extension names, log lines) that makes an agent following `SKILL.md` delete files, upload data, change settings, or run commands without the user's approval. Also in scope: text that gets past the cleaning in `clean()` in `scan.py` (control or invisible characters, line breaks, or length limits) and reaches the agent unchanged.
- **Safety rule bypass**: any path where the skill deletes, quarantines, uploads, elevates privileges, installs software, or changes security settings without explicit user consent.
- **Data leaks**: anything that sends information off the device other than what the user approved (VirusTotal lookups send only a file hash).
- **Local data exposure**: baseline snapshots or tool installs written somewhere other users or programs can read or tamper with.

Out of scope (please open a normal issue, or report to the right project):

- **Missed malware or wrong detections.** Detection is done by the antivirus engines and rule sets. Report missed samples or false detections to [Microsoft](https://www.microsoft.com/wdsi/filesubmission), [ClamAV](https://www.clamav.net/reports/malware), or [YARA Forge](https://github.com/YARAHQ/yara-forge). False alarms from this skill's own heuristics (startup items, extensions) are welcome as regular issues.
- **Vulnerabilities in third-party tools** (Microsoft Defender, ClamAV, Loki-RS, Lynis, rkhunter, VirusTotal): report them to those projects.
- **Behavior of the AI agent itself** (Claude Code, Codex, Cursor, and others) that is not caused by this skill's instructions: report it to the agent's vendor.
- Findings that need an attacker who already has administrator or root access to the machine being checked.

## Security design

For context when reviewing or testing:

- **Report only.** The skill never deletes, quarantines, stops programs, installs software, updates definitions, elevates privileges, or changes security settings without the user's explicit approval. It never runs `sudo` itself.
- **Scanned content is data, not instructions.** `SKILL.md` tells the agent to treat everything read from the computer as untrusted and to show suspicious instructions to the user instead of following them.
- **Verified downloads.** The only tool the skill downloads is ClamAV, from the official Cisco Talos GitHub release, checked against the release's SHA-256 before use and only with the user's approval. Archives are extracted with path checks. Loki-RS is never downloaded by the skill (the user installs it manually). Nothing executable is bundled in this repository.
- **Hostile text is cleaned.** Names, paths, commands, and tool output from the scanned computer pass through `clean()` in `scan.py`, which replaces control and invisible characters, joins lines, and shortens long text. Every command's output also carries a notice that this text is data. `SKILL.md` tells the agent never to follow it. This lowers the risk; it does not remove it.
- **Nothing leaves the device by default.** Files are never uploaded. Optional VirusTotal lookups send only a SHA-256 hash, and only with the user's own API key.
- **Local, per-user state.** Baselines and tool installs live in the user's own data folder (for example `%LOCALAPPDATA%\device-checkup`).
- **Standard library only.** `scan.py` has no third-party Python dependencies.

## Not a replacement for antivirus

This skill is a checkup aid, not real-time protection, and it cannot guarantee a device is free of malware. If you believe your device is actively compromised: disconnect it from the internet, change important passwords from a different, clean device, back up your files, and consider professional help or a clean reinstall.
