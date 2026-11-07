# phishing-triage-lab

<p align="center">
  <img alt="shield logo" src="https://img.shields.io/badge/🛡️-offline%20triage-0F172A?style=for-the-badge&labelColor=111827&color=38bdf8" />
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

Safe, offline defensive security tooling for authorized lab use. This project helps with:

- URL triage using text-only heuristics
- static inspection of local HTML files
- read-only file triage and SHA-256 hashing
- red-team exercise planning without live testing
- blue-team tabletop and hardening guidance

> This project is for learning, research, and defensive training only. It does not execute suspicious files, visit URLs, exfiltrate data, or delete files.

## Project goals

- Keep analysis fully offline and local.
- Favor static inspection over execution.
- Produce heuristic findings that must be reviewed manually.
- Support safe red/blue lab workflows without live exploitation.

## Included tools

- `red-blue-tool`: interactive menu for URL, HTML, file, hash, planning, and security guidance.
- `phishing_check.py`: static URL and saved-HTML inspection.
- `scanner.py`: read-only file triage for suspicious local files.

## Quick start

### Kali Linux

```bash
git clone https://github.com/huynhanonimous-jpg/phishing-triage-lab.git
cd phishing-triage-lab
python3 -m venv .venv
source .venv/bin/activate
python red-blue-tool
```

### Windows PowerShell

```powershell
git clone https://github.com/huynhanonimous-jpg/phishing-triage-lab.git
cd phishing-triage-lab
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python .\red-blue-tool
```

If PowerShell blocks activation, run:

```powershell
.\.venv\Scripts\python.exe .\red-blue-tool
```

## Example commands

```bash
python phishing_check.py "https://example.com/login"
python phishing_check.py "https://example.com/login" --html-file ./saved-page.html --json reports/url-report.json
python scanner.py ./sample.exe --json reports/file-report.json
```

## Safety notes

- Only inspect URLs/files that you are authorized to review.
- The tool does not resolve domains, open browser windows, execute scripts, or send telemetry.
- HTML analysis is static and text-only.
- File triage is heuristic and not a replacement for antivirus or incident response tooling.
- Do not automatically delete files based on the score; keep backups and follow your organization's policies.

## Menu options

The CLI menu includes:

1. URL check (offline heuristics)
2. Local HTML inspection
3. Local file triage
4. SHA-256 hash calculation
5. Red-team exercise planner (written scope only)
6. Blue-team tabletop exercise
7. Defensive hardening checklist
8. Export the last result as JSON

## License

MIT. See [LICENSE](LICENSE).
