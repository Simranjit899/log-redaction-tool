# Log Redaction Tool

A simple CLI tool to redact secrets and PII from log files.

## Features
- Redacts email addresses
- Redacts IPv4 addresses
- Redacts password-like fields (password=, pwd:, pass:)

## Usage
```bash
python3 redact.py sample.log.example
