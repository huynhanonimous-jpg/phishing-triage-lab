import argparse
import hashlib
import json
import zipfile
from pathlib import Path

MAX_SAMPLE_BYTES = 4 * 1024 * 1024

INDICATORS = (
    b"powershell",
    b"cmd.exe",
    b"rundll32",
    b"writeprocessmemory",
    b"virtualalloc",
    b"createremotethread",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identify_type(path: Path, sample: bytes) -> str:
    if sample.startswith(b"MZ"):
        return "Windows PE candidate"
    if sample.startswith(b"\x7fELF"):
        return "ELF executable candidate"
    if sample.startswith(b"PK\x03\x04") and zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as archive:
                if "AndroidManifest.xml" in archive.namelist():
                    return "Android APK candidate"
        except (OSError, zipfile.BadZipFile):
            pass
        return "ZIP archive"
    return "Unknown / other"


def scan(path: Path) -> dict:
    if not path.is_file():
        raise ValueError("Path is not a regular file.")

    with path.open("rb") as file:
        sample = file.read(MAX_SAMPLE_BYTES)

    lower_sample = sample.lower()
    matches = [
        indicator.decode("ascii")
        for indicator in INDICATORS
        if indicator in lower_sample
    ]

    return {
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "type_guess": identify_type(path, sample),
        "heuristic_indicators": matches,
        "assessment": "Needs manual review" if matches else "No indicators found in sampled bytes",
        "note": (
            "Heuristic result only; it is not proof that a file is safe or malicious. "
            "Only the first 4 MiB are checked for these text indicators."
        ),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Read-only static file triage; never executes or deletes files."
    )
    parser.add_argument("file", help="Path to a file to inspect")
    parser.add_argument("--json", dest="json_path", help="Optional JSON report path")
    args = parser.parse_args()

    try:
        result = scan(Path(args.file))
    except (OSError, ValueError) as error:
        parser.error(str(error))

    output = json.dumps(result, indent=2, ensure_ascii=False)
    print(output)
    if args.json_path:
        output_path = Path(args.json_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
        print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
