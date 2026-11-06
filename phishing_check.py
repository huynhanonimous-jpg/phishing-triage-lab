import argparse
import ipaddress
import json
import re
import unicodedata
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

MAX_HTML_BYTES = 2 * 1024 * 1024
SUSPICIOUS_TERMS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "password", "passwd", "account", "secure", "security", "wallet",
    "recovery", "mfa", "otp", "update-payment",
)


class StaticHTMLInspector(HTMLParser):
    """Collect simple HTML indicators without executing code or fetching resources."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts = []
        self.forms = []
        self.links = []
        self.external_scripts = []
        self.iframes = []
        self.password_fields = 0
        self.hidden_fields = 0
        self._in_title = False
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = dict(attrs)

        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").lower(),
                "has_password_field": False,
            }
            self.forms.append(self._current_form)
        elif tag == "input":
            input_type = attrs.get("type", "text").lower()
            if input_type == "password":
                self.password_fields += 1
                if self._current_form is not None:
                    self._current_form["has_password_field"] = True
            if input_type == "hidden":
                self.hidden_fields += 1
        elif tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "script" and attrs.get("src"):
            self.external_scripts.append(attrs["src"])
        elif tag == "iframe" and attrs.get("src"):
            self.iframes.append(attrs["src"])

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)


def _host(url):
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _is_ip_address(host):
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def inspect_url(raw_url):
    candidate = raw_url.strip()
    if not candidate:
        raise ValueError("URL is empty.")
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        raise ValueError("URL contains a control character.")
    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
        # Accessing .port also validates malformed port numbers.
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"Invalid URL: {error}") from error

    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are accepted.")
    if not host:
        raise ValueError("URL must contain a hostname.")

    findings = []
    score = 0

    if parsed.username is not None or parsed.password is not None:
        findings.append({"severity": "high", "detail": "URL contains user-info before the hostname."})
        score += 25

    if _is_ip_address(host):
        findings.append({"severity": "medium", "detail": "Hostname is an IP address rather than a domain name."})
        score += 15

    try:
        ascii_host = host.encode("idna").decode("ascii")
        if "xn--" in ascii_host.lower():
            findings.append({"severity": "medium", "detail": "Hostname contains an IDN/punycode label; check for look-alike characters."})
            score += 15
    except UnicodeError:
        findings.append({"severity": "medium", "detail": "Hostname contains characters that could not be normalized with IDNA."})
        score += 15

    unusual_chars = sorted({
        f"U+{ord(char):04X} {unicodedata.name(char, 'UNKNOWN')}"
        for char in candidate
        if ord(char) > 127 and not char.isspace()
    })
    if unusual_chars:
        findings.append({
            "severity": "info",
            "detail": "Non-ASCII characters found; inspect carefully for look-alikes.",
            "characters": unusual_chars[:30],
        })
        score += 5

    if port is not None and port not in (80, 443):
        findings.append({"severity": "low", "detail": f"URL uses a non-standard web port ({port})."})
        score += 5

    if "%" in candidate:
        findings.append({"severity": "info", "detail": "Percent-encoded characters are present; inspect the decoded destination carefully."})
        score += 3

    if len(host.split(".")) >= 5:
        findings.append({"severity": "low", "detail": "Hostname has many subdomain levels."})
        score += 5

    lowered = candidate.lower()
    found_terms = [term for term in SUSPICIOUS_TERMS if term in lowered]
    if found_terms:
        findings.append({"severity": "info", "detail": "URL contains terms often used in credential/payment lures.", "terms": found_terms})
        score += min(5 * len(found_terms), 20)

    if not findings:
        findings.append({"severity": "info", "detail": "No configured URL heuristics matched; this does not establish safety."})

    return {
        "input_url": raw_url,
        "normalized_url": candidate,
        "hostname": host,
        "findings": findings,
        "risk_score": min(score, 100),
        "assessment": _assessment(score),
        "network_access": "none",
        "note": "Heuristic triage only. The URL was not resolved, visited, or verified against a threat-intelligence service.",
    }


def _assessment(score):
    if score >= 40:
        return "Elevated indicators; review carefully"
    if score >= 15:
        return "Some indicators; review manually"
    return "No or few indicators; not a safety verdict"


def inspect_local_html(html_path, base_url):
    path = Path(html_path)
    if not path.is_file():
        raise ValueError("HTML path is not a regular file.")
    if path.stat().st_size > MAX_HTML_BYTES:
        raise ValueError(f"HTML file exceeds the {MAX_HTML_BYTES}-byte size limit.")

    text = path.read_text(encoding="utf-8", errors="replace")
    parser = StaticHTMLInspector()
    parser.feed(text)
    parser.close()

    page_host = (_host(base_url) or "").lower().rstrip(".")

    def summarize_targets(values):
        results = []
        for value in values:
            value = value.strip()
            if not value:
                continue
            absolute = urljoin(base_url, value)
            target_host = (_host(absolute) or "").lower().rstrip(".")
            results.append({
                "reference": value,
                "hostname": target_host or None,
                "cross_host": bool(target_host and page_host and target_host != page_host),
            })
        return results

    forms = []
    for form in parser.forms:
        action = form["action"].strip()
        absolute_action = urljoin(base_url, action) if action else base_url
        action_host = (_host(absolute_action) or "").lower().rstrip(".")
        forms.append({
            "action": action or "(same page/default)",
            "method": form["method"],
            "has_password_field": form["has_password_field"],
            "cross_host": bool(action_host and page_host and action_host != page_host),
            "target_hostname": action_host or None,
        })

    findings = []
    if parser.password_fields:
        findings.append("Password input field(s) found; verify the page and form destination.")
    if any(form["cross_host"] and form["has_password_field"] for form in forms):
        findings.append("A form containing a password field submits to a different hostname.")
    if any(item["cross_host"] for item in summarize_targets(parser.external_scripts)):
        findings.append("External script reference(s) point to a different hostname.")
    if parser.iframes:
        findings.append("Iframe(s) found; inspect their source hostnames.")

    return {
        "local_html_file": path.name,
        "page_url_context": base_url,
        "title": " ".join(" ".join(parser.title_parts).split())[:300],
        "password_fields": parser.password_fields,
        "hidden_fields": parser.hidden_fields,
        "forms": forms,
        "links": summarize_targets(parser.links)[:100],
        "external_scripts": summarize_targets(parser.external_scripts)[:100],
        "iframes": summarize_targets(parser.iframes)[:100],
        "findings": findings or ["No configured HTML heuristics matched; this does not establish safety."],
        "network_access": "none",
        "note": "Local HTML parsed as text only. Scripts and resources were not executed or fetched.",
    }


def main():
    parser = argparse.ArgumentParser(description="Offline URL and local HTML phishing triage.")
    parser.add_argument("url", help="URL to inspect as text; the tool never visits it")
    parser.add_argument("--html-file", help="Optional local HTML file to parse statically")
    parser.add_argument("--json", dest="json_path", help="Optional path to save a JSON report")
    args = parser.parse_args()

    try:
        report = {"url_analysis": inspect_url(args.url)}
        if args.html_file:
            report["html_analysis"] = inspect_local_html(args.html_file, report["url_analysis"]["normalized_url"])
    except (OSError, ValueError) as error:
        parser.error(str(error))

    output = json.dumps(report, indent=2, ensure_ascii=False)
    print(output)
    if args.json_path:
        output_path = Path(args.json_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
        print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
