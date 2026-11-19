# device-checkup-skill

**Ask your AI agent to check your computer for viruses and suspicious programs.**
Works on Windows, macOS, and Linux. Built on the open [Agent Skills](https://agentskills.io) format, so it works with Claude Code, Codex, Cursor, Windsurf, Antigravity, and other agents that support skills.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Format](https://img.shields.io/badge/format-Agent%20Skills-purple)
[![Tests](https://github.com/rzrabbi/device-checkup-skill/actions/workflows/tests.yml/badge.svg)](https://github.com/rzrabbi/device-checkup-skill/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.9%2B%20(optional)-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-lightgrey)

`device-checkup` gives an AI agent a safe, repeatable way to check the computer it is running on. It runs a real antivirus engine (Microsoft Defender or ClamAV), reviews the programs that start automatically, inspects network connections, and explains everything in plain language.

Just say:

> **"Run a device checkup."**

## Why

Most people don't know what is running on their computer, and security tools are written for experts. This skill lets you ask in plain words and get a clear, ranked answer: what was checked, what looks odd, what it means, and what to do next.

The antivirus engine does the detecting. The agent runs it, reads the results, and explains them. The agent is not a virus scanner by itself, and this skill never pretends otherwise.

## What it checks

| Area | What happens |
|---|---|
| **Viruses and malware** | Runs Microsoft Defender (Windows) and/or ClamAV (any OS) on the folders you choose |
| **Startup programs** | Checks everywhere programs hide to start automatically, and flags unusual ones. Windows: Run keys (including 32-bit and policy keys), startup folders, scheduled tasks, services, Winlogon, debugger hijacks, AppInit DLLs, WMI subscriptions. Linux: cron, systemd units and timers, autostart, SSH keys, shell startup files, `ld.so.preload`. macOS: launchd, Login Items, configuration profiles, SSH keys, shell startup files |
| **Security settings** | Checks firewall, real-time and tamper protection, virus definition age, OS updates, pending restart, disk encryption (BitLocker, FileVault, LUKS), SmartScreen, UAC, Gatekeeper, SIP, Secure Boot, and Remote Desktop, with plain-language advice for each |
| **Browser extensions** | Lists extensions in Chrome, Edge, Brave, Vivaldi, Opera, Firefox, and Safari, and flags the adware tricks: force-installed by policy ("managed by your organization"), sideloaded, or unsigned |
| **Network** | Lists listening ports with the program behind each, plus active connections, so unexpected ones stand out |
| **Changes since last time** | Saves a local snapshot after each checkup, so the next one can report what changed, for example "2 new startup programs, firewall turned off, new program listening on port 4444" |
| **Second-opinion scan** | Optional [Loki-RS](https://github.com/Neo23x0/Loki-RS) scan with YARA Forge rules and known-bad indicators, on any OS |
| **Linux and macOS audit** | Optional [Lynis](https://cisofy.com/lynis/) security audit and [rkhunter](https://rkhunter.sourceforge.net/) rootkit check |
| **Suspicious files** | Looks up a file's SHA-256 fingerprint on VirusTotal (optional). The file itself is never uploaded |
| **Report** | The same clear layout every time: overall verdict, what needs attention, security settings, changes, scan results, what was not checked, and next steps |

## Quick start

1. [Install the skill](#install).
2. Open your AI agent and ask one of these:
   - "Run a device checkup."
   - "Is my computer infected?"
   - "Are my security settings OK?"
   - "Why does my browser say it's managed by my organization?"
   - "What changed on my computer since the last checkup?"
   - "What programs start automatically on my computer?"
   - "Check my Downloads folder for viruses."
   - "Is this file safe?" (give it a file path)
3. Follow along. The agent explains each step and asks before doing anything that needs permission.

## Install

Requires an AI agent that supports [Agent Skills](https://agentskills.io). Python 3.9 or newer is recommended.

**No Python? No problem.** The agent checks for it first. If it's missing, the agent offers to install it for your account only (no administrator password; from the official Python package via `winget` on Windows, Apple's command-line tools on macOS). If you'd rather not, it runs a shorter **basic checkup** using only built-in commands: antivirus status and a quick scan, firewall, updates, disk encryption, startup programs, network listeners, and forced browser extensions. The report says clearly what the basic checkup could not cover.

### Option 1: one command (recommended)

Use the [`skills`](https://github.com/vercel-labs/skills) CLI. It detects which agents you have installed and puts the skill in the right folder for each.

```bash
npx skills add rzrabbi/device-checkup-skill
```

To target one agent, pass it explicitly, for example `-a claude-code`. If you run the command from inside an agent session, name the agent explicitly, otherwise it may install only to the shared `.agents/skills/` folder, which not every agent reads.

### Option 2: copy the folder by hand

Clone the repo and copy `skills/device-checkup` into your agent's skills folder.

| Agent | Skills folder (personal) | Skills folder (one project) |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Codex and other agents using the shared convention | `~/.agents/skills/` | `.agents/skills/` |
| Antigravity | `~/.gemini/config/skills/` | `.agents/skills/` |
| Cursor, Windsurf, Copilot, others | Use Option 1, or check your agent's skills documentation | |

Agents change these locations between versions. If a folder doesn't work, use Option 1 or check your agent's documentation.

**macOS / Linux** (example for Claude Code)

```bash
git clone https://github.com/rzrabbi/device-checkup-skill
mkdir -p ~/.claude/skills && cp -r device-checkup-skill/skills/device-checkup ~/.claude/skills/
```

**Windows (PowerShell)** (example for Claude Code)

```powershell
git clone https://github.com/rzrabbi/device-checkup-skill
Copy-Item -Recurse device-checkup-skill\skills\device-checkup "$env:USERPROFILE\.claude\skills\device-checkup"
```

Start a new agent session, then ask for a device checkup.

### Agents without skill support

Point your agent at [`AGENTS.md`](AGENTS.md) or at `skills/device-checkup/SKILL.md` and ask it to follow that file. The workflow and safety rules work as plain instructions, and the helper script is standard Python.

### Antivirus engines

| System | Engine | Setup |
|---|---|---|
| Windows | Microsoft Defender | Included with Windows 10/11 (may be off if another antivirus is installed) |
| Windows | ClamAV (optional) | Installed by the skill on request: official build, checksum verified, no admin needed |
| macOS | ClamAV | Installed by the skill on request via Homebrew (`brew install clamav`) |
| Linux | ClamAV | The skill shows the command for your distro (for example `sudo apt install clamav`) |
| All | Loki-RS (optional second opinion) | Installed by the skill on request: official build, checksum verified, no admin needed |
| Linux, macOS | Lynis, rkhunter (optional audits) | The skill shows the install command; rkhunter checks need root |
| Windows | Emsisoft Emergency Kit (optional) | Manual only: the agent explains how to download and run it from emsisoft.com |

You don't need to install ClamAV yourself. When it's needed, the agent shows you the download size and source and asks first. The virus database is kept in a folder owned by the skill and is only updated when it is more than 6 hours old.

If another antivirus (Norton, McAfee, and so on) has turned Defender off, the skill can't drive that product. It tells you how to run a scan in your antivirus app, and offers ClamAV as a second opinion. The other checks work as usual.

### Optional: VirusTotal lookups

Set a free VirusTotal API key as the `VT_API_KEY` environment variable. Only file hashes are sent, never your files.

## How it works

```
 You: "Run a device checkup"
          │
          ▼
   Agent follows SKILL.md
          │
          ▼
 scripts/scan.py  ──►  Defender / ClamAV   (real detection)
          │       ──►  startup + services + scheduled tasks
          │       ──►  security settings (firewall, updates, encryption)
          │       ──►  browser extensions
          │       ──►  compare with last checkup (local snapshot)
          │       ──►  network connections
          │       ──►  optional VirusTotal hash lookup
          ▼
   Agent reads the JSON results,
   explains them in plain language,
   ranks findings, lists what was not checked
```

`SKILL.md` holds the workflow and the safety rules. `scripts/scan.py` is a small Python helper (standard library only) that prints JSON.

| Command | Purpose |
|---|---|
| `engines` | Detect Defender, ClamAV, and other antivirus; definition age; Defender exclusions |
| `update [--force]` | Update virus definitions (ClamAV only when older than 6 hours) |
| `clamav-setup [--yes]` | Plan, then (after approval) install ClamAV for this user |
| `loki-setup [--yes]` | Plan, then (after approval) install Loki-RS for this user |
| `audit` | Lynis security audit (Linux, macOS) |
| `rootkit [--from-file F]` | rkhunter rootkit check (Linux, macOS; needs root, or reads output you saved) |
| `scan --path P [--engine auto\|defender\|clamav\|loki\|both\|all]` | Scan a folder |
| `persistence [--include-system]` | List startup items, scheduled tasks, services, cron, launchd, with plain-language reasons for each flag |
| `posture [--check-updates]` | Check security settings; `--check-updates` also lists pending OS updates |
| `network` | List listening ports (with program names) and connections |
| `extensions [--include-builtin]` | List browser extensions with access level and red flags |
| `baseline save\|diff\|list` | Save a local snapshot, or show what changed since the last one |
| `hash FILE [--vt]` | SHA-256 and optional VirusTotal lookup |

## Safety by design

- **Report only.** The agent asks before it deletes, quarantines, stops a program, disables a task, installs software, updates definitions, or uses administrator rights.
- **No file uploads.** Nothing leaves your computer without your explicit approval. Hash lookups send only the fingerprint.
- **Snapshots stay local.** Baselines are saved in your user data folder (for example `%LOCALAPPDATA%\device-checkup` on Windows) and never sent anywhere. Set `DEVICE_CHECKUP_DIR` to store them elsewhere.
- **Verified downloads only.** ClamAV and Loki-RS come only from their official GitHub releases and are checked against their SHA-256 before use. Nothing is bundled in this repo, so you always get the latest patched version.

Found a security problem in the skill itself? Please report it privately; see [SECURITY.md](SECURITY.md).
- **Scanned content is data, not instructions.** Text inside files, scripts, filenames, or logs cannot give the agent commands.
- **Suspicious files are never run.**
- **Honest results.** The skill never says "you are safe". It says what was checked, what was found, and what was not covered.

## Limitations

- Antivirus catches known threats. New, hidden, or targeted malware can be missed.
- Flags on startup items are pattern matches, not verdicts. Normal software such as installers and developer tools can trigger them.
- ClamAV has weaker Windows coverage than Defender or commercial products.
- No deep scan of firmware, the operating system core, or hidden rootkits. For a deeper check, use an offline scan such as Microsoft Defender Offline or a rescue disk.
- Full scans and Defender scans usually need administrator rights, and the skill will not elevate by itself.
- This is a checkup, not a replacement for always-on antivirus.

## Repository layout

```
device-checkup-skill/
├── README.md
├── AGENTS.md                 # for agents without skill support
├── SECURITY.md               # how to report vulnerabilities
├── LICENSE
├── .github/workflows/
│   └── tests.yml             # CI: Windows, macOS, Linux
├── tests/                    # unit + smoke tests (standard library only)
└── skills/
    └── device-checkup/
        ├── SKILL.md          # skill instructions and safety rules
        └── scripts/
            └── scan.py       # cross-platform helper, JSON output
```

## Running the tests

No extra packages needed. From the repository root:

```bash
python -m unittest discover -s tests -v
```

Unit tests use fake registries, profiles, and command output, so they run on any OS. Smoke tests run the real read-only commands on your machine (no downloads, no scans, no system changes; baselines go to a temporary folder). CI runs everything on Windows, macOS, and Linux.

Test inputs that look like malware command lines are assembled at runtime from pieces (see `tests/helpers.py`), so antivirus software does not flag the repository.

## Contributing

Issues and pull requests are welcome. Good first contributions:

- Test on macOS or Linux and report what breaks
- Test in other agents and report install paths that work
- Add more persistence locations or detection patterns
- Add more AV engines (for example, rkhunter or chkrootkit on Linux)
- Improve the plain-language explanations in `SKILL.md`

Keep the helper dependency-free and keep the safety rules intact: report only, no uploads, no execution of suspect files.

## Disclaimer

This skill is provided as is, for personal use, without warranty. It is a checkup aid and does not guarantee that a device is free of malware. If you suspect an active infection, disconnect from the internet, change important passwords from a different clean device, back up your files, and consider professional help or a clean reinstall.

## License

[MIT](LICENSE)
