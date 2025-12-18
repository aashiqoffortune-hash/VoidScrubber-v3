# RepoCleaner v3

RepoCleaner v3 is a compact, single-file Python utility for identifying and removing tool-generated traces (watermarks, badges, metadata) and common secret-like patterns from source repositories — safely and reproducibly.

---

## Features

- Prioritized pattern scanning (Lovable watermarks first, then other AI traces, then secret-like patterns)
- Atomic file writes, optional backups, and dry-run mode for safe previews
- Vulnerability scanning via Bandit (Python) and `npm audit` (JS) with optional auto-fix
- Optional JS/CSS minification when `--obfuscate` is enabled (requires npm tools)
- Custom pattern support via JSON (`{"patterns": ["regex1","regex2"]}`)

---

## Quick Start

Requirements: Python 3.8+. Optional: `git`, `npm` for audits/obfuscation.

```bash
# Preview changes without making edits
python3 repo_cleaner.py --dry-run --verbose

# Run cleanup with a backup and auto-commit
python3 repo_cleaner.py --backup --commit --verbose
```

---

## Common Flags

- `--dry-run, -d`  Preview changes
- `--backup`       Create timestamped ZIP backup
- `--commit, -c`   Stage, commit, and attempt to push changes
- `--obfuscate, -o` Minify JS/CSS (requires `uglify-js` / `clean-css-cli`)
- `--log-file, -l FILE`  Write a JSON log of changes
- `--pattern-file FILE`  Load additional detection patterns

See `python3 repo_cleaner.py --help` for a full list.

---

## Safety Notes

- Writes are atomic and backups are preserved when requested.
- The tool avoids modifying unsupported file types and aims to keep code functional.
- Prefer running on a clone/feature branch when using `--commit` and `--push`.

---

## Contributing & Tests

Contributions welcome. Please include tests for new patterns or behavior. Run tests with:

```bash
python3 repo_cleaner.py --test
# or
pytest -q
```

---

## License

MIT — see `LICENSE`.

---

If you prefer a different tone, more examples, or project badges, tell me how you'd like it styled and I will update it.