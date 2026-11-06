# phishing-triage-lab

A small, dependency-free defensive triage project for inspecting URLs and local HTML files, plus hashing and basic file triage. It does **not** visit URLs, execute JavaScript, run samples, decrypt files, delete files, or upload data.

> Heuristic findings are clues for manual review, not proof that a URL/file is malicious or safe. Do not open suspicious files or submit private URLs/files to public services without authorization.

## Features

- URL-only checks for unusual characters, punycode/IDN, IP-literal hosts, credentials in URLs, uncommon ports, and suspicious URL terms.
- Optional static inspection of a **local HTML file** you already have: forms, password fields, external links/scripts, iframes, hidden inputs, and title. HTML is parsed as text; scripts are never executed and no network requests are made.
- File triage: SHA-256, file size/type guess, and a few text indicators in the first 4 MiB. No files are modified.
- JSON output for saving reports.
- Python standard library only; runs on Kali Linux and Windows.

## Kali Linux setup

```bash
git clone https://github.com/huynhanonimous-jpg/phishing-triage-lab.git
cd phishing-triage-lab
python3 -m venv .venv
source .venv/bin/activate
```

No third-party packages are required.

## Windows PowerShell setup

```powershell
git clone https://github.com/huynhanonimous-jpg/phishing-triage-lab.git
cd phishing-triage-lab
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If activation is blocked, invoke Python directly with `\.venv\Scripts\python.exe`.

## Check a URL (no network access)

```bash
python phishing_check.py "https://example.com/login?next=%2F"
```

PowerShell:

```powershell
python .\phishing_check.py "https://example.com/login?next=%2F"
```

The URL is analyzed as text only. The tool does not resolve the domain, connect to it, follow redirects, or retrieve its page.

## Inspect a saved HTML file locally

Save the page source through a trusted method, then inspect the local file alongside the URL it claims to represent:

```bash
python phishing_check.py "https://example.com/login" --html-file ./page-source.html --json reports/url-report.json
```

Do not open or execute suspicious HTML in a browser to obtain it. The tool only parses a local text file and does not load external resources.

## Triage a file without executing it

```bash
python scanner.py ./sample.exe --json reports/file-report.json
```

The file scanner checks a small set of text indicators in at most the first 4 MiB. A lack of indicators does **not** mean the file is safe; this is not an antivirus replacement.

## Safety and privacy

- Use only with URLs/files you are authorized to inspect.
- This project makes no network requests and sends no telemetry.
- Reports may contain sensitive URLs, paths, or metadata; review before sharing.
- Do not automatically delete files based on heuristic scores. Use reputable endpoint protection and backups.

## License

MIT. See [LICENSE](LICENSE).
