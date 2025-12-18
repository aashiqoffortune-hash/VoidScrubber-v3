# RepoCleaner v3 — ShadowVault Optimizer 🔎🛡️

**RepoCleaner v3** (a.k.a. ShadowVault Optimizer) is a lightweight, single-file Python tool to scan repositories for tool-generated traces (watermarks, badges, metadata, and common secret patterns) and remove them safely while preserving functional code and repo integrity.

---

## ✨ Key Capabilities

- Detects and removes watermarks and traces (Lovable, Copilot, GPT, Cursor, Replit, etc.)
- Scans common text file types: `.html`, `.js`, `.jsx`, `.ts`, `.tsx`, `.css`, `.md`, `.mdx`, `.json`, `.svg`, `.yaml`, `.yml`, `.toml`, `.config`, `.txt`
- Performs security checks (Bandit for Python and `npm audit` for JS projects)
- Safe operation modes: **dry-run**, **backups**, **atomic writes**, and **git-friendly commits**
- Optional obfuscation/minification for JS and CSS (requires `uglify-js` / `clean-css-cli` via npm)
- Custom pattern support via JSON pattern file

---

## 🚀 Quick Start

Requirements:
- Python 3.8+
- Optional: `git`, `npm` (for JS audits and obfuscation tools)

Download or clone this repo and run from the target project root:

```bash
# Preview changes (DRY-RUN): see what would be changed
python3 repo_cleaner.py --dry-run --verbose

# Run actual cleanup with backup and auto-commit (safe default if not dry-run)
python3 repo_cleaner.py --backup --commit --verbose
```

Notes:
- `--dry-run` will only report changes and will not write files.
- `--backup` creates a timestamped ZIP archive of the repository before modification.
- `--commit` will stage, commit, and attempt to push changes (uses random decoy committer identity by default).

---

## 🧭 Options & Flags

Use `python3 repo_cleaner.py --help` for a full list. Common flags include:

- `--dry-run, -d`         Preview changes without applying them
- `--commit, -c`          Auto-commit & push changes (respects `--dry-run`)
- `--bundle, -b`          Create a ZIP bundle after processing
- `--backup`              Make a secure backup before any modifications
- `--verbose, -v`         Increase log verbosity
- `--new-dir, -n DIR`     Copy processed repository to `DIR` instead of modifying in place
- `--log-file, -l FILE`   Save a JSON log of all changes
- `--eta`                 Show ETA during processing
- `--obfuscate, -o`       Attempt to minify JS/CSS (requires npm tools)
- `--vuln-scan, -s`       Run vulnerability scans (Bandit / npm audit)
- `--auto-patch, -a`      Attempt auto-fix for found vulns (when supported)
- `--pattern-file FILE`   Load custom JSON patterns (format: {"patterns": ["regex1","regex2"]})

---

## ✅ Safety & Guarantees

- All file writes are done atomically to prevent partial writes.
- Backups are created (when requested) so you can restore state.
- Binary files and unsupported extensions are skipped automatically.
- The tool attempts to preserve syntax and avoid modifications likely to break code (e.g., does not minify TypeScript by default).

---

## 🔎 How Detection Works

- The tool ships a prioritized list of regex patterns (Lovable watermarks first, other AI traces, then secret-like patterns).
- `detailed_scan()` records exact file/line locations and returns types detected.
- `clean_file()` removes matches using atomic write, logs changes, and optionally runs minification for JS/CSS when `--obfuscate` is enabled.

---

## 🧪 Testing

A small pytest suite is included to validate pattern loading, cleaning behavior, and core helpers. To run tests:

```bash
# Ensure pytest is available, then run:
python3 repo_cleaner.py --test
# or
pytest -q
```

Note: The script auto-installs `pytest` if invoked via `--test` and not present (may require network access).

---

## 🛠️ Examples

Preview and log changes:

```bash
python3 repo_cleaner.py . --dry-run --verbose --log-file changes.json
```

Full cleanup with backup and vulnerability scan:

```bash
python3 repo_cleaner.py /path/to/repo --backup --commit --vuln-scan --auto-patch --verbose
```

Export cleaned repo to a new folder:

```bash
python3 repo_cleaner.py . --new-dir ../clean-export --bundle
```

---

## ⚠️ Limitations & Notes

- The tool is focused on text-based traces; it does not attempt to analyze binary blobs, archives, or externally hosted assets.
- Minification/obfuscation is best-effort and requires external npm tools; failures are non-fatal and logged.
- Be cautious with `--commit` and `--push` on sensitive or production branches — prefer running on a clone or feature branch first.

---

## Contributing

Contributions are welcome:
- Open an issue if you find a false positive/negative or want new detection patterns added.
- Submit PRs to add patterns, tune behavior, or improve tests.

Please include test cases for detection tweaks.

---

## License

This project is distributed under the MIT License — see the `LICENSE` file for details.

---

If you want a custom README tweak (more examples, different tone, or additional badges), tell me the preferred style and I will update it. 