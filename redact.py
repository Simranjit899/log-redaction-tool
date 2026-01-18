#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

# --- Detection patterns (v1) ---
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Authorization header redaction (Bearer / Basic)
AUTH_HEADER_RE = re.compile(r"(?i)\bAuthorization\s*:\s*(Bearer|Basic)\s+([^\s]+)")

# Generic key/value secret fields (api_key=..., token:..., secret=...)
SECRET_FIELD_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret)\b\s*([=:])\s*([^\s,;]+)"
)

# Some well-known token prefixes (high confidence)
GITHUB_TOKEN_RE = re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
SLACK_TOKEN_RE = re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")

# Matches common "password-like" fields in logs: password=..., pwd: ..., pass: ...
# Captures the key separately so we can keep it and only redact the value.
PASSWORD_FIELD_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|pass)\b\s*([=:])\s*([^\s,;]+)"
)

def redact_text(text: str) -> str:
    """
    Apply redactions to a chunk of text.
    Order matters: we redact structured key/value fields first, then broad patterns.
    """
    # Redact password-like fields while keeping the key and separator
    def _pw_sub(m: re.Match) -> str:
        key = m.group(1)
        sep = m.group(2)
        return f"{key}{sep}[REDACTED_PASSWORD]"

    text = PASSWORD_FIELD_RE.sub(_pw_sub, text)
        # Redact Authorization headers
    def _auth_sub(m: re.Match) -> str:
        scheme = m.group(1)
        return f"Authorization: {scheme} [REDACTED_AUTH_TOKEN]"
    text = AUTH_HEADER_RE.sub(_auth_sub, text)

    # Redact generic secret fields while keeping the key and separator
    def _secret_sub(m: re.Match) -> str:
        key = m.group(1)
        sep = m.group(2)
        return f"{key}{sep}[REDACTED_SECRET]"
    text = SECRET_FIELD_RE.sub(_secret_sub, text)

    # Redact known token formats
    text = GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", text)
    text = SLACK_TOKEN_RE.sub("[REDACTED_SLACK_TOKEN]", text)


    # Redact emails and IPs
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = IPV4_RE.sub("[REDACTED_IP]", text)

    return text

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Redact secrets and PII from log files (v1: email, IPv4, password fields)."
    )
    parser.add_argument("input", help="Input log file path")
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <input>.redacted)",
        default=None
    )
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists() or not in_path.is_file():
        print(f"Error: input file not found: {in_path}")
        return 2

    out_path = Path(args.output) if args.output else in_path.with_suffix(in_path.suffix + ".redacted")

    data = in_path.read_text(encoding="utf-8", errors="replace")
    redacted = redact_text(data)
    out_path.write_text(redacted, encoding="utf-8")

    print(f"Redacted file written to: {out_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
