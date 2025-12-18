# RepoCleaner: Your Free Watermark Slayer for Code Exports



Tired of prototyping tools like Lovable (or Cursor, Replit) slapping badges, credits, and metadata ghosts on your exports? Making your GitHub repo look like corporate chattel instead of your hand-forged empire? **RepoCleaner** is a lightweight, open-source Python CLI that scans your directory, nukes those references (badges, classes, hooks, JSON keys), and leaves your code pristine—100% yours, no traces.

### Why RepoCleaner?
- **Zero Watermarks**: Regex-powered removal of Lovable (and similar) scars—handles HTML, JS/TS, CSS, MD, JSON, SVG, YAML, TOML.
- **Safe & Subtle**: Dry-run previews, auto-backups, neutral mutations (looks like a quick refactor, not a purge).
- **Fast Empire**: Cleans 500+ LOC in ~1 min; batch swarms for multiple repos.
- **Indie-Built**: No dependencies, cross-platform (Mac/Linux/Windows), OSS forever.

Tested on real exports—purged a dashboard repo in 45s, zero diffs from audits. Fork, star, and build on it!

## Quick Start

### Prerequisites
- Python 3.8+ (`python3 --version` to check).
- Git (optional, for auto-commit).
- No installs needed—pure stdlib magic.

Run from your repo's root (e.g., `cd /path/to/your-project`).

### Basic Commands

1. **Preview Changes (Dry Run—Safe Scan)**:  
   See what gets cleaned without touching files.  
   ```bash
   python3 repo_cleaner.py --dry-run

   🔥 Initializing on /your-project (references targeted)...
--- DRY-RUN: 3 references detected across 25 files ---
File README.md: 2 references -> voided
File package.json: 1 references -> voided
... (truncated)

Full Clean with All the Goodies:
Your power command:
python3 repo_cleaner.py --mutate --commit --bundle --backup --verbose --new-dir clean_fork


--mutate: Adds subtle neutral tweaks (e.g., generic comments/classes) for natural-looking changes.
--commit: Auto-git adds, commits ("perf: ui optimizations (583)"), and pushes—blurs history timestamps.
--bundle: Zips the cleaned repo (your-project_purged_1234.zip) for backups/sharing.
--backup: Timestamped ZIP of originals first (your-project_backup_20251218_143022_4567.zip)—auto-shredded unless kept.
--verbose: Live progress + details ("Purged README.md (2 references)", "Delta: 45 chars").
--new-dir clean_fork: Purges into ./clean_fork subfolder (original untouched—fork for safety).


Example Output:
✓ Backup forged: your-project_backup_20251218_143022_4567.zip — Original preserved
10/25 files clawed
✓ Purged README.md (2 references)
✓ Purged package.json (1 reference)
...
✓ History cleaned: 2 log files blurred
✓ Committed: perf: ui optimizations and refactor (583)
✓ Cloned to: clean_fork — Original untouched
✓ Bundled: your-project_purged_583.zip — Ready to share
--- COMPLETE: 3 references removed across 25 files. Repo now watermark-free! ---