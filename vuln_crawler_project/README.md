# Vulnerability Crawler & Notifier (PyQt6)

A standalone Python application that fetches high‑value vulnerabilities for **today** (or a user‑selected date) from five intelligence feeds, deduplicates them, and displays the results in an interactive GUI with automatic 30‑minute refresh.

## Quick‑start

```bash
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Tested on Python 3.9 – 3.13, macOS & Windows 10.
