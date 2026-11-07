# phishing-triage-lab

<p align="center">
  <img alt="shield logo" src="https://img.shields.io/badge/🛡️-offline%20triage-0F172A?style=for-the-badge&labelColor=111827&color=38bdf8" />
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

Safe, offline defensive security tooling for authorized lab use. The project includes URL/file triage, a manual internal-web review checklist, defensive Wi-Fi configuration guidance, red-team exercise planning, and blue-team remediation worksheets.

> This is a learning aid, not a vulnerability scanner or security verdict. It does not scan networks, test live services, execute suspicious files, or attempt Wi-Fi access. Use only assets you own or are explicitly authorized to review.

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

No third-party packages are required. If PowerShell blocks activation, use `\.venv\Scripts\python.exe .\red-blue-tool`.

## Example commands

```bash
python phishing_check.py "https://example.com/login"
python phishing_check.py "https://example.com/login" --html-file ./saved-page.html --json reports/url-report.json
python scanner.py ./sample.exe --json reports/file-report.json
```

## Menu

1. URL check — offline text heuristics; no DNS or HTTP request.
2. Local HTML inspection — parse saved HTML as text; no scripts/resources loaded.
3. File triage — hash, type guess, and limited text indicators; file remains unchanged.
4. SHA-256 calculation.
5. Authorized red-team exercise planning — scope and safety paperwork only.
6. Blue-team incident-response tabletop.
7. General defensive hardening checklist.
8. Export the latest result to JSON.
9. Internal web security review checklist — manual configuration/code review prompts; no live testing.
10. Wi-Fi security hardening checklist — defensive router configuration guidance; no wireless discovery or connection attempts.
11. Vulnerability remediation worksheet for tracking owner, fix, and safe validation.

## Safety and scope

- Obtain written authorization and a clearly defined scope before assessing any system.
- This project intentionally does not probe internal/external networks, crawl websites, test vulnerabilities, capture Wi-Fi traffic, or attempt access.
- Use vendor-supported admin consoles and approved non-production processes for technical validation.
- Findings are prompts for human review, not proof that a system is vulnerable or safe.
- Do not put credentials, private keys, or sensitive personal data into prompts or exported reports.

## License

MIT. See [LICENSE](LICENSE).
