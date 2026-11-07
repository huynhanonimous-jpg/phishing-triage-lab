# phishing-triage-lab

A small, dependency-free defensive security learning project for Kali Linux and Windows. Run the menu with `python red-blue-tool`. It combines offline phishing/file triage with safe red-team exercise planning and blue-team tabletop guidance.

> This is a learning aid, not an antivirus or a security verdict. Heuristics can be wrong. Use only systems and files you are authorized to inspect.

## What it does

The interactive menu provides eight options:

1. Analyze a URL as text only (no DNS lookup or connection).
2. Inspect a saved local HTML file as text (no browser, script execution, or resource loading).
3. Read-only file triage: SHA-256, type guess, and a few indicators in the first 4 MiB.
4. Calculate a local file's SHA-256.
5. Create a written red-team exercise scope/authorization checklist; performs no technical testing.
6. Run a blue-team incident-response tabletop prompt.
7. Show a defensive hardening checklist.
8. Export the latest result to JSON.

No network scanning, exploit, payload, credential collection, sample execution, file deletion, or telemetry is included. The project uses only Python's standard library.

## Kali Linux

```bash
git clone https://github.com/huynhanonimous-jpg/phishing-triage-lab.git
cd phishing-triage-lab
python3 -m venv .venv
source .venv/bin/activate
python red-blue-tool
```

You can also run the individual analyzers:

```bash
python phishing_check.py "https://example.com/login"
python phishing_check.py "https://example.com/login" --html-file ./saved-page.html --json reports/url.json
python scanner.py ./sample.exe --json reports/file.json
```

## Windows PowerShell

```powershell
git clone https://github.com/huynhanonimous-jpg/phishing-triage-lab.git
cd phishing-triage-lab
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python .\red-blue-tool
```

If PowerShell blocks venv activation, run `\.venv\Scripts\python.exe .\red-blue-tool` instead.

## Safe use

- Use only with URLs, files, and systems you are authorized to assess.
- URL inspection is offline and text-only; it does not establish whether a site is safe.
- HTML is parsed locally; do not open suspicious files in a browser to prepare them.
- File checks are basic heuristics and are not a replacement for reputable endpoint protection.
- Do not automatically delete files based on a score. Keep backups and follow your organization's incident process.
- Reports can contain private URLs or paths; inspect them before sharing.

## License

MIT. See [LICENSE](LICENSE).
