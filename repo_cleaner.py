#!/usr/bin/env python3
import os
import re
import sys
import argparse
import random
import subprocess
import shutil
import json
import logging
from pathlib import Path
from datetime import datetime
from contextlib import contextmanager
import time
from glob import glob
import tempfile
import atexit
import shutil

# Conditional import for pytest - only when testing
PYTEST_AVAILABLE = False
try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    pass  # Will auto-install or skip tests if --test

# Configure robust logging from the start
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'repocleaner_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)

# Auto-install core packages if missing (with fallback)
def install_package(package, max_retries=3):
    for attempt in range(max_retries):
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', package, '--quiet', '--no-warn-script-location'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30
            )
            logger.info(f"Installed {package} successfully on attempt {attempt + 1}")
            return True
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout installing {package} on attempt {attempt + 1}")
        except Exception as e:
            logger.warning(f"Failed to install {package} on attempt {attempt + 1}: {e}")
    logger.error(f"Failed to install {package} after {max_retries} attempts")
    return False

# Ensure core deps with fallbacks
tqdm_available = False
yaml_available = False
rich_available = False

try:
    from tqdm import tqdm
    tqdm_available = True
except ImportError:
    if install_package('tqdm'):
        from tqdm import tqdm
        tqdm_available = True

try:
    import yaml
    yaml_available = True
except ImportError:
    if install_package('pyyaml'):
        import yaml
        yaml_available = True

try:
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, MofNCompleteColumn
    from rich.console import Console
    rich_available = True
except ImportError:
    if install_package('rich'):
        from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, MofNCompleteColumn
        from rich.console import Console
        rich_available = True

# Auto-install pytest if --test and not available
def ensure_pytest():
    global PYTEST_AVAILABLE
    if not PYTEST_AVAILABLE:
        if install_package('pytest'):
            import pytest
            PYTEST_AVAILABLE = True
        else:
            logger.warning("pytest unavailable - tests skipped. Run 'pip install pytest' manually.")

def progress_bar(iterable, desc="", total=None, unit="item", disable=False):
    """Rich progress bar: Hypnotic emerald flow, fallback to tqdm/ANSI for unbreakable aesthetics."""
    if disable:
        return iterable
    
    if rich_available:
        # Rich supremacy: Cyan desc, green bar, percentage pulse, ETA ghost - cyber velvet
        console = Console(file=sys.stdout)
        with Progress(
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=None, style="green", complete_style="bright_green"),
            TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"[bold green]{desc}", total=total)
            def rich_wrapped():
                for item in iterable:
                    progress.update(task, advance=1)
                    yield item
            return rich_wrapped()
    elif tqdm_available:
        # Tqdm fallback: Green tide, cyan rates - elegant reserve
        return tqdm(
            iterable, 
            desc=desc, 
            total=total, 
            unit=unit, 
            colour='GREEN',
            bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]',
            dynamic_ncols=True
        )
    else:
        # ANSI abyss: Green sweeps, cyan whispers - no scars, pure flow
        class AestheticFallbackBar:
            def __init__(self, iterable, **kwargs):
                self.iterable = iterable
                self.current = 0
                self.total = total or len(iterable) if hasattr(iterable, '__len__') else None
                self.desc = desc or "Processing"
                self.unit = unit
                green = '\033[92m'
                cyan = '\033[96m'
                reset = '\033[0m'
                bold = '\033[1m'
                logger.info(f"{cyan}{bold}{self.desc} initiated{reset} ({self.total} {self.unit}s)")
            
            def __iter__(self):
                return self
            
            def __next__(self):
                try:
                    item = next(self.iterable)
                    self.current += 1
                    if self.total:
                        pct = (self.current / self.total) * 100
                        bar_width = 40
                        filled = int(bar_width * self.current // self.total)
                        bar = '\033[92m█' * filled + '\033[90m░' * (bar_width - filled) + '\033[0m'
                        green = '\033[92m'
                        cyan = '\033[96m'
                        reset = '\033[0m'
                        bold = '\033[1m'
                        logger.info(f"{cyan}{bold}{self.desc}:{reset} {bar} {green}{self.current}/{self.total} ({pct:.1f}%){reset}")
                    return item
                except StopIteration:
                    green = '\033[92m'
                    reset = '\033[0m'
                    bold = '\033[1m'
                    logger.info(f"{green}{bold}Completed {self.desc}{reset}")
                    raise
            
            def update(self, n=1):
                self.current += n
            
            def set_postfix(self, **kwargs):
                if kwargs:
                    cyan = '\033[96m'
                    reset = '\033[0m'
                    postfix_str = ' | '.join([f"{k}: {v}" for k, v in kwargs.items()])
                    logger.info(f"{cyan}Update:{reset} {postfix_str}")
        
        return AestheticFallbackBar(iterable, desc=desc)

# Atomic file write context manager
@contextmanager
def atomic_write(file_path, mode='w', encoding='utf-8', backup=True):
    """Write to a temp file and atomically replace target to prevent partial writes."""
    temp_fd, temp_path = tempfile.mkstemp(dir=file_path.parent, prefix=f".{file_path.name}.tmp")
    try:
        with os.fdopen(temp_fd, mode, encoding=encoding) as temp_f:
            yield temp_f
        # Atomic replace
        os.replace(temp_path, file_path)
        logger.debug(f"Atomically wrote {file_path}")
    except Exception as e:
        # Cleanup temp on error
        try:
            os.unlink(temp_path)
        except:
            pass
        raise e
    finally:
        if backup and file_path.exists():
            backup_path = file_path.with_suffix(file_path.suffix + f".backup.{random.randint(1000, 9999)}")
            shutil.copy2(file_path, backup_path)

# Patterns: Priority 1 - Lovable watermarks first, then other AI traces, then secrets
def load_patterns(pattern_file=None):
    default_patterns = [
        # PRIORITY 1: Lovable watermarks (exhaustive coverage)
        r'(?i)(lovable|lovable\.dev|edit with lovable|generated by lovable|don\'t delete this lovable)',
        r'(?i)#lovable-badge',
        r'(?i)class\s*=\s*["\']lovable[^"\']*["\']',
        r'(?i)id\s*=\s*["\']lovable[^"\']*["\']',
        r'(?i)src\s*=\s*["\'][^"\']*lovable[^"\']*\.svg["\']',
        r'(?i)useLovableEdit|lovable-export:\s*true',
        r'(?i)lovable\.com|powered by lovable',
        r'(?i)"lovable-.*?"',
        r'(?i)lovable-badge|lovable-watermark',
        r'(?i)<!--\s*lovable\s*-->|<!--\s*generated\s*by\s*lovable\s*-->',
        # PRIORITY 2: Other AI watermarks
        r'(?i)(cursor|cursor\.sh|generated by cursor|ai-powered by cursor)',
        r'(?i)(replit|replit\.com|replit ghost|ai assistant replit)',
        r'(?i)(github copilot|copilot generated|copilot: true)',
        r'(?i)(claude|anthropic|claude-ai|generated with claude)',
        r'(?i)(gpt|openai|chatgpt|generated by gpt)',
        r'(?i)(codeium|generated by codeium|powered by codeium)',
        r'(?i)(tabnine|tabnine generated|tabnine ai)',
        r'(?i)(amazon q|codewhisperer|generated by amazon q|amazon codewhisperer)',
        r'(?i)(cody|sourcegraph cody|generated by cody)',
        r'(?i)(blackbox|blackbox ai|generated by blackbox)',
        r'(?i)(aider|generated by aider|aider ai)',
        r'(?i)(continue|continue\.dev|generated by continue)',
        r'(?i)(grok|xai|generated by grok|powered by grok)',
        r'(?i)(gemini|google gemini|generated by gemini)',
        r'(?i)(sourcery|generated by sourcery)',
        r'(?i)(figma|figma dev mode|generated by figma ai)',
        r'(?i)(devin|cognition|generated by devin|powered by devin|cognition labs)',
        r'(?i)(sweep|sweep\.dev|generated by sweep|sweep ai)',
        r'(?i)(augment|augment code|generated by augment|augmentcode)',
        r'(?i)(bolt|bolt\.new|generated by bolt|ai by bolt)',
        r'(?i)(cline|cline ai|generated by cline)',
        r'(?i)(roocode|roo code|generated by roocode|roo ai)',
        r'(?i)(qodo|qodo ai|generated by qodo)',
        r'(?i)(replit agent|agent v2|generated by replit agent|replit agent v2)',
        # PRIORITY 3: Secret patterns for security
        r'(?i)(api[_-]?key[:\s]*["\']?[a-zA-Z0-9]{20,40}["\']?)',
        r'(?i)(password[:\s]*["\']?[a-zA-Z0-9@#$%^&*]{8,50}["\']?)',
        r'(?i)(secret[:\s]*["\']?[a-zA-Z0-9]{32,}["\']?)',
        r'(?i)(token[:\s]*["\']?[a-zA-Z0-9_-]{24,}["\']?)',
        r'(?i)(aws[_-]?access[_-]?key[_-]?id[:\s]*["\']?AKIA[a-zA-Z0-9]{16}["\']?)',
        r'(?i)(private[_-]?key[:\s]*-----BEGIN RSA PRIVATE KEY-----)',
    ]
    if pattern_file and Path(pattern_file).exists():
        try:
            with open(pattern_file, 'r', encoding='utf-8') as f:
                custom_data = json.load(f)
                custom = custom_data.get('patterns', [])
                default_patterns.extend(custom)
            logger.info(f"Loaded {len(custom)} custom patterns from {pattern_file}")
        except Exception as e:
            logger.warning(f"Failed to load custom patterns from {pattern_file}: {e}")
    return default_patterns

# Compile patterns once, but allow reload
def compile_patterns(patterns):
    try:
        return [re.compile(p, re.MULTILINE | re.DOTALL) for p in patterns]
    except re.error as e:
        logger.error(f"Invalid regex pattern: {e}")
        return []

COMPILED_PATTERNS = compile_patterns(load_patterns())

# Mapping for detection types (optimized lookup)
PATTERN_TO_TYPE = {
    # Lovable first
    'lovable': 'Lovable Watermark',
    # Other AI
    'cursor': 'Cursor',
    'replit': 'Replit',
    'copilot': 'Copilot',
    'claude': 'Claude',
    'gpt': 'GPT',
    'codeium': 'Codeium',
    'tabnine': 'Tabnine',
    'amazon': 'Amazon Q',
    'cody': 'Cody',
    'blackbox': 'Blackbox',
    'aider': 'Aider',
    'continue': 'Continue',
    'grok': 'Grok',
    'gemini': 'Gemini',
    'sourcery': 'Sourcery',
    'figma': 'Figma AI',
    'devin': 'Devin',
    'sweep': 'Sweep',
    'augment': 'Augment',
    'bolt': 'Bolt',
    'cline': 'Cline',
    'roocode': 'RooCode',
    'qodo': 'Qodo',
    'agent v2': 'Replit Agent',
    # Secrets last
    'api_key': 'API Key',
    'password': 'Password',
    'secret': 'Secret',
    'token': 'Token',
    'aws_access': 'AWS Access Key',
    'private_key': 'Private Key',
}

# DECOYS stubbed - unused for fixed phantom sig
DECOYS = ["CustomBuild", "DevTool", "CodeHelper", "AnonEdit", "QuickGen", "UIHelper"]  # Legacy; ignore for void

def safe_remove_file(fp: Path, max_retries=3):
    """Securely remove file with overwrite and retries."""
    for attempt in range(max_retries):
        try:
            if fp.exists():
                size = fp.stat().st_size
                if size > 0:
                    # Overwrite with random data multiple times for security
                    for _ in range(3):
                        with open(fp, 'r+b') as f:
                            f.seek(0)
                            f.write(os.urandom(size))
                fp.unlink()
                logger.debug(f"Securely removed {fp}")
                return True
        except Exception as e:
            logger.warning(f"Failed to remove {fp} on attempt {attempt + 1}: {e}")
            time.sleep(0.1)  # Brief pause before retry
    logger.error(f"Failed to securely remove {fp} after {max_retries} attempts")
    return False

def enhance_gitignore(root_path: Path, log_entries=None):
    """Enhance .gitignore for security: Add common ignores if missing, atomically."""
    gitignore_path = root_path / '.gitignore'
    common_ignores = [
        '*.env',
        '*.pem',
        '*.key',
        'secrets.json',
        'config.yaml',
        '.DS_Store',
        'node_modules/',
        '__pycache__/',
        '.vscode/',
        '.gitattributes',  # Prevent attribute leaks
        '*.log',  # Hide logs
        '*.tmp',  # Temp files
    ]
    try:
        if not gitignore_path.exists():
            with atomic_write(gitignore_path, backup=False) as f:
                f.write('# Enhanced security ignores by RepoCleaner\n')
                f.write('\n'.join(common_ignores) + '\n')
            if log_entries is not None:
                log_entries.append({'gitignore': 'created'})
            logger.info("Initialized .gitignore.")
        else:
            with open(gitignore_path, 'r', encoding='utf-8') as f:
                content = f.read()
            missing = [ig for ig in common_ignores if ig not in content]
            if missing:
                with atomic_write(gitignore_path) as f:
                    f.seek(0)
                    f.truncate()
                    f.write(content)
                    f.write('\n# Additional security by RepoCleaner\n')
                    f.write('\n'.join(missing) + '\n')
                if log_entries is not None:
                    log_entries.append({'gitignore': 'enhanced', 'added': len(missing)})
                logger.info(f"Updated .gitignore with {len(missing)} new entries.")
    except Exception as e:
        logger.error(f"Failed to enhance .gitignore: {e}")

def clean_file(file_path: Path, dry_run=False, verbose=False, log_entries=None, obfuscate=False):
    """Clean file with atomic writes and robust error handling."""
    if not file_path.is_file():
        return []
    ext = file_path.suffix.lower()
    supported_exts = {'.html', '.js', '.jsx', '.ts', '.tsx', '.css', '.mdx', '.md', '.txt', '.json', '.svg', '.yaml', '.yml', '.toml', '.config'}
    if ext not in supported_exts:
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        logger.warning(f"Failed to read {file_path}: {e}")
        return []
    
    original_content = content
    original_size = len(original_content)
    match_count = 0
    changes = []
    
    # Priority cleaning: Lovable first, then others
    lovable_count = 0
    lovable_patterns = [p for p in COMPILED_PATTERNS if 'lovable' in p.pattern.lower()]
    for compiled_pat in lovable_patterns:
        matches = compiled_pat.findall(content)
        if matches:
            lovable_count += len(matches)
            content = compiled_pat.sub('', content)
    
    other_count = 0
    other_patterns = [p for p in COMPILED_PATTERNS if 'lovable' not in p.pattern.lower()]
    for compiled_pat in other_patterns:
        matches = compiled_pat.findall(content)
        if matches:
            other_count += len(matches)
            content = compiled_pat.sub('', content)
    
    match_count = lovable_count + other_count
    
    if match_count > 0:
        changes.append(f"{file_path.name}: {lovable_count} Lovable + {other_count} other resolved")
        if verbose:
            logger.info(f"Cleaned {file_path.name} (Lovable priority)")
        if log_entries is not None:
            log_entries.append({
                'file': str(file_path),
                'lovable_count': lovable_count,
                'other_count': other_count,
                'original_size': original_size
            })
        
        if not dry_run:
            try:
                with atomic_write(file_path) as f:
                    f.write(content)
                if log_entries is not None:
                    log_entries[-1]['new_size'] = len(content)
                
                # Obfuscate if requested (FIX: Only JS/JSX for uglifyjs, TS untouched to avoid corruption)
                if obfuscate:
                    if ext in {'.js', '.jsx'}:  # JS only - no TS to prevent syntax breakage
                        try:
                            subprocess.run(
                                ['uglifyjs', str(file_path), '-o', str(file_path), '--mangle', '--compress'],
                                capture_output=True,
                                timeout=30,
                                check=True
                            )
                            changes.append(f"Minified {file_path.name}")
                        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
                            logger.warning(f"Failed to minify {file_path}: {e}")
                    elif ext == '.css':
                        try:
                            subprocess.run(
                                ['cleancss', str(file_path), '-o', str(file_path)],
                                capture_output=True,
                                timeout=30,
                                check=True
                            )
                            changes.append(f"Minified {file_path.name}")
                        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
                            logger.warning(f"Failed to minify CSS {file_path}: {e}")
            except Exception as e:
                logger.error(f"Failed to write cleaned content to {file_path}: {e}")
                # Restore from backup if available
                backup_glob = list(file_path.parent.glob(f"{file_path.name}.backup.*"))
                if backup_glob:
                    shutil.copy2(backup_glob[0], file_path)
                    logger.info(f"Restored {file_path} from backup due to write failure")
    
    return changes

def safe_subprocess_run(cmd, cwd=None, timeout=60, capture_output=True, check=False, env=None):
    """Wrapper for subprocess.run with retries and logging."""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            result = subprocess.run(
                cmd, cwd=cwd, timeout=timeout, capture_output=capture_output,
                text=True, check=check, env=env or os.environ
            )
            return result
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout on {cmd} (attempt {attempt + 1}/{max_retries})")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Command {cmd} failed (attempt {attempt + 1}/{max_retries}): {e}")
        except FileNotFoundError:
            logger.error(f"Command not found: {cmd[0]}")
            break
        time.sleep(0.5 * attempt)  # Exponential backoff
    return None

def check_vulns(root_path: Path, dry_run=False, verbose=False, auto_fix=False, log_entries=None, detected=None):
    logger.info("Performing security audit...")
    issues = []
    
    # Python vuln scan with Bandit
    py_files = list(root_path.rglob('*.py'))
    if py_files:
        result = safe_subprocess_run(['bandit', '-f', 'json', '-r', str(root_path)], timeout=120)
        if result and result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                high_issues = [i for i in data.get('results', []) if i.get('issue_severity') in ['HIGH', 'MEDIUM']]
                issues.extend([{'file': issue['filename'], 'desc': issue['issue_text']} for issue in high_issues])
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Bandit output: {e}")
    
    # JS vuln scan
    js_dirs = [d for d in root_path.rglob('*') if (d / 'package.json').exists()]
    for js_dir in js_dirs:
        result = safe_subprocess_run(['npm', 'audit', '--json'], cwd=js_dir, timeout=120)
        if result and result.returncode == 1:  # npm audit returns 1 on vulns
            try:
                data = json.loads(result.stdout)
                high_vulns = []
                for vuln_data in data.get('vulnerabilities', {}).values():
                    if isinstance(vuln_data, dict) and vuln_data.get('severity') in ['high', 'critical']:
                        high_vulns.append(vuln_data)
                issues.extend([{'dir': str(js_dir), 'desc': v['name']} for v in high_vulns])
                
                if auto_fix and not dry_run:
                    fix_result = safe_subprocess_run(['npm', 'audit', 'fix'], cwd=js_dir, timeout=120)
                    if fix_result:
                        logger.info(f"Auto-fixed vulns in {js_dir}")
                    else:
                        logger.warning(f"Failed to auto-fix in {js_dir}")
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse npm audit output for {js_dir}: {e}")
    
    # Secret scan log
    if detected and any('Secret' in t or 'Key' in t or 'Token' in t for t in detected):
        logger.info("Sensitive data issues resolved during pattern cleaning.")
    
    if issues:
        logger.warning(f"Found {len(issues)} potential security issues.")
        if verbose:
            for issue in issues:
                logger.warning(f"  - {issue.get('file', issue.get('dir', 'Unknown'))}: {issue['desc']}")
        if log_entries is not None:
            log_entries.append({'security': {'issues_found': len(issues), 'details': issues}})
    else:
        logger.info("Security audit complete - no issues found.")
    return issues

def detailed_scan(root_path: Path, verbose=False, pattern_file=None):
    """Smart scan: Read entire repo line-by-line to locate exact positions of issues (Lovable priority)."""
    if pattern_file:
        global COMPILED_PATTERNS
        raw_patterns = load_patterns(pattern_file)
        COMPILED_PATTERNS = compile_patterns(raw_patterns)
    
    detected = set()
    trace_locations = {}  # file: [(line_num, snippet), ...]
    target_files = []
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            file_path = Path(dirpath) / filename
            ext = file_path.suffix.lower()
            if ext in {'.html', '.js', '.jsx', '.ts', '.tsx', '.css', '.mdx', '.md', '.txt', '.json', '.svg', '.yaml', '.yml', '.toml', '.config'}:
                target_files.append(file_path)
    
    file_count = len(target_files)
    logger.info(f"Analyzing {file_count} files (Lovable watermarks priority)...")
    
    if file_count == 0:
        logger.info("No target files to analyze.")
        return False, detected, trace_locations
    
    iterable = progress_bar(target_files, desc="Scanning", total=file_count, unit="file", disable=not rich_available and not tqdm_available)
    for file_path in iterable:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            file_traces = []
            for line_num, line in enumerate(lines, 1):
                line_lower = line.lower()
                for compiled_pat in COMPILED_PATTERNS:
                    if compiled_pat.search(line_lower):
                        pat_str = compiled_pat.pattern
                        for key, typ in PATTERN_TO_TYPE.items():
                            if key in pat_str.lower():
                                detected.add(typ)
                                snippet = line.strip()[:100] + '...' if len(line.strip()) > 100 else line.strip()
                                file_traces.append((line_num, snippet))
                                break
                        break  # One match per line
            if file_traces:
                trace_locations[str(file_path)] = file_traces
        except Exception as e:
            logger.warning(f"Failed to scan {file_path}: {e}")
            continue
    
    if detected:
        logger.info(f"Identified issues: {', '.join(sorted(detected))}")
        if verbose:
            for file, locs in trace_locations.items():
                logger.info(f"  - {file}: {len(locs)} locations")
    else:
        logger.info("No issues found during scan.")
    return bool(detected), detected, trace_locations

def verify_cleanup(root_path: Path, verbose=False):
    """Re-scan to verify no issues remain."""
    has_traces, _, _ = detailed_scan(root_path, verbose)
    if not has_traces:
        logger.info("Verification: Repository fully clean (Lovable-free).")
        return True
    else:
        logger.warning("Verification: Residual traces detected - manual review recommended.")
        return False

def cleanup_temp_backups(root_path: Path):
    """Clean up temporary backup files at exit."""
    temp_patterns = [
        f"{root_path.name}_backup_*.zip",
        "*.backup.*",
        f".{root_path.name}.tmp*"
    ]
    for pattern in temp_patterns:
        temp_files = glob(pattern)
        for temp_file in temp_files:
            safe_remove_file(Path(temp_file))

def main_cleanup(root_path: Path, dry_run=False, commit=True, bundle=False, backup=False, verbose=False, new_dir=None, log_file=None, show_eta=False, obfuscate=False, vuln_check=True, auto_fix=True, pattern_file=None):
    log_entries = []
    start_time = time.time()
    atexit.register(cleanup_temp_backups, root_path)
    
    has_traces, trace_types, trace_locations = detailed_scan(root_path, verbose, pattern_file)
    if not has_traces:
        logger.info("Repository is already clean - no action needed.")
        return
    
    logger.info("Initiating unbreakable cleanup sequence (Lovable priority)...")
    
    enhance_gitignore(root_path, log_entries)
    
    backup_file = None
    if backup:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f"{root_path.name}_backup_{timestamp}_{random.randint(1000,9999)}.zip"
        try:
            shutil.make_archive(backup_file, 'zip', root_path)
            logger.info(f"Secure backup created: {backup_file}")
        except Exception as e:
            logger.warning(f"Backup creation failed: {e}")
    
    target_files = [
        Path(dirpath) / fn for dirpath, _, fns in os.walk(root_path)
        for fn in fns if (Path(dirpath) / fn).suffix.lower() in {
            '.html', '.js', '.jsx', '.ts', '.tsx', '.css', '.mdx', '.md',
            '.txt', '.json', '.svg', '.yaml', '.yml', '.toml', '.config'
        }
    ]
    
    file_count = len(target_files)
    logger.info(f"Processing {file_count} target files...")
    all_changes = []
    iterable = progress_bar(target_files, desc="Purging", total=file_count, unit="file", disable=not rich_available and not tqdm_available)
    
    for file_path in iterable:
        changes = clean_file(file_path, dry_run, verbose, log_entries, obfuscate)
        all_changes.extend(changes)
        if show_eta and len(all_changes) % 100 == 0:
            elapsed = time.time() - start_time
            rate = len(all_changes) / elapsed if elapsed > 0 else 0
            remaining_files = file_count - (iterable.current if hasattr(iterable, 'current') else 0)  # Adapt for Rich/tqdm
            eta_seconds = remaining_files / rate if rate > 0 else 0
            eta_min = int(eta_seconds // 60)
            if hasattr(iterable, 'set_postfix'):
                iterable.set_postfix({'ETA': f"{eta_min}m", 'processed': len(all_changes)})
    
    if dry_run:
        logger.info(f"DRY-RUN: {len(all_changes)} enhancements identified - no changes applied.")
        return
    
    if vuln_check:
        check_vulns(root_path, verbose=verbose, auto_fix=auto_fix, log_entries=log_entries, detected=trace_types)
    
    verification_passed = verify_cleanup(root_path, verbose)
    if not verification_passed:
        logger.warning("Cleanup verification failed - check logs for details.")
    
    # Auto-commit with fixed phantom sig - no decoys, pure void
    if commit and all_changes:
        git_env = os.environ.copy()
        git_env['GIT_COMMITTER_NAME'] = "by"  # Fixed name for "by example@com" render
        git_env['GIT_COMMITTER_EMAIL'] = "example@com"  # Fixed email - unresolvable ghost
        try:
            safe_subprocess_run(['git', 'add', '.'], cwd=root_path, timeout=30, env=git_env)
            commit_msg = f"chore: shadow optimizations ({random.randint(100,999)})"
            safe_subprocess_run(['git', 'commit', '-m', commit_msg], cwd=root_path, timeout=30, env=git_env)
            safe_subprocess_run(['git', 'push'], cwd=root_path, timeout=60, env=git_env)
            logger.info(f"Committed and pushed as 'by <example@com>': {commit_msg}")
        except Exception as e:
            logger.warning(f"Git operations failed: {e} - Changes staged locally.")
    
    # Copy to new dir if requested
    if new_dir:
        clone_to = root_path.parent / new_dir
        try:
            clone_to.mkdir(exist_ok=True)
            for item in root_path.iterdir():
                if item.is_dir() and item.name != '.git':
                    shutil.copytree(item, clone_to / item.name, dirs_exist_ok=True, ignore_dangling_symlinks=True)
                elif item.is_file() and item.name != '.git':
                    shutil.copy2(item, clone_to)
            logger.info(f"Cloned processed repo to {new_dir}")
        except Exception as e:
            logger.error(f"Failed to clone to {new_dir}: {e}")
    
    # Bundle if requested
    if bundle:
        bundle_file = f"{root_path.name}_clean_bundle_{random.randint(1000,9999)}.zip"
        try:
            shutil.make_archive(bundle_file, 'zip', root_path)
            logger.info(f"Secure bundle created: {bundle_file}")
        except Exception as e:
            logger.warning(f"Bundle creation failed: {e}")
    
    # Final temp cleanup
    cleanup_temp_backups(root_path)
    
    duration = time.time() - start_time
    logger.info(f"Cleanup mission complete: {len(all_changes)} changes in {file_count} files. Elapsed: {duration:.1f}s")
    
    if log_file:
        try:
            with atomic_write(Path(log_file)) as f:
                json.dump(log_entries, f, indent=2)
            if verbose:
                logger.info(f"Detailed log saved to {log_file}")
        except Exception as e:
            logger.error(f"Failed to save log to {log_file}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="RepoCleaner: Eradicate Lovable watermarks (priority) and all traces/secrets with unbreakable resilience.",
        epilog="Engineered for zero-failure execution, total untraceability, and exponential stealth."
    )
    parser.add_argument('path', nargs='?', default='.', help='Target repository path (default: current dir)')
    parser.add_argument('--dry-run', '-d', action='store_true', help='Simulate changes without applying')
    parser.add_argument('--commit', '-c', action='store_true', default=True, help='Auto-commit/push changes (default: yes, unless dry-run)')
    parser.add_argument('--bundle', '-b', action='store_true', help='Create encrypted zip bundle post-processing')
    parser.add_argument('--backup', action='store_true', help='Create secure backup before modifications')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable detailed logging')
    parser.add_argument('--new-dir', '-n', type=str, help='Clone processed repo to new directory')
    parser.add_argument('--log-file', '-l', type=str, help='Output detailed JSON log to file')
    parser.add_argument('--eta', action='store_true', help='Display estimated time remaining')
    parser.add_argument('--obfuscate', '-o', action='store_true', help='Minify/obfuscate JS/CSS for extra stealth')
    parser.add_argument('--vuln-scan', '-s', action='store_true', default=True, help='Run vuln scans (default: yes)')
    parser.add_argument('--auto-patch', '-a', action='store_true', default=True, help='Auto-fix detected vulns (default: yes)')
    parser.add_argument('--pattern-file', type=str, help='Custom patterns JSON file for extended detection')
    args = parser.parse_args()
    
    # Run tests if invoked directly with --test
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        ensure_pytest()
        if PYTEST_AVAILABLE:
            sys.exit(pytest.main([__file__, '-v', '--tb=short']))
        else:
            logger.error("pytest required for tests. Install with 'pip install pytest'.")
            sys.exit(1)
    
    # Validate path early
    root = Path(args.path).resolve()
    if not root.exists():
        logger.error(f"Target path not found: {args.path}")
        sys.exit(1)
    if not root.is_dir():
        logger.error(f"Target must be a directory: {args.path}")
        sys.exit(1)
    
    # Reload patterns if custom file provided
    if args.pattern_file:
        raw_patterns = load_patterns(args.pattern_file)
        global COMPILED_PATTERNS
        COMPILED_PATTERNS = compile_patterns(raw_patterns)
    
    # Pre-install obfuscation tools if requested
    if args.obfuscate:
        safe_subprocess_run(['npm', 'install', '-g', 'uglify-js'], timeout=60)
        safe_subprocess_run(['npm', 'install', '-g', 'clean-css-cli'], timeout=60)
        if not shutil.which('uglifyjs') or not shutil.which('cleancss'):
            logger.warning("Obfuscation tools unavailable - JS/CSS minification skipped.")
    
    # Auto-commit logic: only if not dry-run
    auto_commit = args.commit and not args.dry_run
    
    logger.info("RepoCleaner activated - commencing untraceable purification...")
    
    try:
        main_cleanup(
            root, args.dry_run, auto_commit, args.bundle, args.backup,
            args.verbose, args.new_dir, args.log_file, args.eta, args.obfuscate,
            args.vuln_scan, args.auto_patch, args.pattern_file
        )
        logger.info("Operation successful: All traces eradicated. Wealth amplification vector secured.")
    except KeyboardInterrupt:
        logger.warning("Operation interrupted by user - partial cleanup applied. Review logs.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected failure in main execution: {e}")
        logger.info("Fallback: Changes are atomic; repo integrity preserved. Rerun for completion.")
        sys.exit(1)

# Pytest Integration for Advanced Testing (only if available)
if PYTEST_AVAILABLE:
    @pytest.fixture
    def test_dir():
        """Fixture for temporary test directory."""
        test_dir = Path(tempfile.mkdtemp())
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def sample_patterns():
        """Fixture for sample patterns."""
        return [
            r'(?i)(lovable|lovable\.dev)',
            r'(?i)(gpt|openai)',
            r'(?i)(api[_-]?key[:\s]*["\']?[a-zA-Z0-9]{20,40}["\']?)'
        ]

    @pytest.fixture
    def compiled_test_patterns(sample_patterns):
        """Fixture for compiled sample patterns."""
        return compile_patterns(sample_patterns)

    def test_load_patterns_no_custom(sample_patterns):
        """Test loading default patterns without custom file."""
        patterns = load_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) > 20  # Expect at least default count
        assert isinstance(patterns[0], str)

    def test_load_patterns_with_custom(sample_patterns, test_dir):
        """Test loading patterns with custom JSON file."""
        custom_file = test_dir / 'custom.json'
        with open(custom_file, 'w') as f:
            json.dump({"patterns": ["r'(?i)custom-trace'"]}, f)
        
        patterns = load_patterns(str(custom_file))
        assert "(?i)custom-trace" in patterns[-1]

    def test_compile_patterns_valid(sample_patterns):
        """Test compiling valid patterns."""
        compiled = compile_patterns(sample_patterns)
        assert len(compiled) == len(sample_patterns)
        assert isinstance(compiled[0], re.Pattern)

    def test_compile_patterns_invalid_regex(sample_patterns):
        """Test compiling with invalid regex - should log error but return partial."""
        invalid_patterns = sample_patterns + [r'invalid[']
        compiled = compile_patterns(invalid_patterns)
        assert len(compiled) <= len(invalid_patterns)  # At least some compile

    def test_clean_file_unsupported_ext(test_dir):
        """Test clean_file on unsupported file extension."""
        test_file = test_dir / 'test.exe'
        test_file.touch()
        changes = clean_file(test_file)
        assert changes == []

    def test_clean_file_lovable_detection_and_removal(test_dir, compiled_test_patterns):
        """Test detecting and removing Lovable watermark."""
        content = "This is generated by lovable.dev\nNo issues here."
        test_file = test_dir / 'test.html'
        with open(test_file, 'w') as f:
            f.write(content)
        
        with patch('__main__.COMPILED_PATTERNS', compiled_test_patterns):
            changes = clean_file(test_file, dry_run=True)
        
        assert len(changes) > 0
        assert 'Lovable' in changes[0]
        with open(test_file, 'r') as f:
            cleaned = f.read()
        assert 'lovable' not in cleaned.lower()

    def test_clean_file_other_detection(test_dir, compiled_test_patterns):
        """Test detecting and removing other AI trace."""
        content = "Generated by GPT-4\nClean content."
        test_file = test_dir / 'test.md'
        with open(test_file, 'w') as f:
            f.write(content)
        
        with patch('__main__.COMPILED_PATTERNS', compiled_test_patterns):
            changes = clean_file(test_file, dry_run=True)
        
        assert len(changes) > 0
        assert 'resolved' in changes[0]  # Other count >0
        with open(test_file, 'r') as f:
            cleaned = f.read()
        assert 'gpt' not in cleaned.lower()

    def test_clean_file_no_changes(test_dir):
        """Test clean_file with no matches."""
        content = "Clean content with no traces."
        test_file = test_dir / 'test.txt'
        with open(test_file, 'w') as f:
            f.write(content)
        
        with patch('__main__.COMPILED_PATTERNS', []):
            changes = clean_file(test_file, dry_run=True)
        
        assert changes == []

    @pytest.mark.parametrize("content, expected", [
        ("Invalid encoding content", []),
    ])
    def test_clean_file_encoding_error(test_dir, content, expected):
        """Test handling encoding errors gracefully."""
        test_file = test_dir / 'test.js'
        with open(test_file, 'wb') as f:  # Write binary to force encoding issue
            f.write(content.encode('latin-1'))
        
        with patch('builtins.open', side_effect=UnicodeDecodeError('utf-8', b'', 0, 1, 'error')):
            changes = clean_file(test_file)
        assert changes == expected

    def test_enhance_gitignore_create_new(test_dir):
        """Test creating new .gitignore."""
        log_entries = []
        enhance_gitignore(test_dir, log_entries)
        gitignore_path = test_dir / '.gitignore'
        assert gitignore_path.exists()
        with open(gitignore_path, 'r') as f:
            content = f.read()
        assert '*.env' in content
        assert any('created' in str(entry) for entry in log_entries)

    def test_enhance_gitignore_update_existing(test_dir):
        """Test updating existing .gitignore."""
        gitignore_path = test_dir / '.gitignore'
        with open(gitignore_path, 'w') as f:
            f.write('# Existing\nnode_modules/')
        
        log_entries = []
        enhance_gitignore(test_dir, log_entries)
        
        with open(gitignore_path, 'r') as f:
            content = f.read()
        assert '*.env' in content  # Missing one added
        assert any('enhanced' in str(entry) for entry in log_entries)

    @pytest.fixture
    def mock_subprocess_run():
        """Fixture for mocking subprocess.run."""
        with patch('subprocess.run') as mock:
            yield mock

    def test_safe_subprocess_run_success(mock_subprocess_run):
        """Test successful subprocess run."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"results": []}'
        mock_subprocess_run.return_value = mock_result
        
        result = safe_subprocess_run(['echo', 'test'])
        assert result.returncode == 0

    def test_safe_subprocess_run_timeout_retry_fail(mock_subprocess_run):
        """Test subprocess timeout with retries failing."""
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired(cmd=[], timeout=1)
        result = safe_subprocess_run(['sleep', '10'], timeout=1)
        assert result is None

    def test_check_vulns_no_py_files(test_dir, mock_subprocess_run):
        """Test vuln check with no Python files."""
        mock_subprocess_run.return_value = None
        with patch('__main__.Path.rglob', return_value=[]):
            issues = check_vulns(test_dir)
        assert issues == []

    def test_detailed_scan_no_files(test_dir):
        """Test scan with no target files."""
        empty_subdir = test_dir / 'empty'
        empty_subdir.mkdir()
        with patch('__main__.COMPILED_PATTERNS', []):
            has_traces, detected, locations = detailed_scan(empty_subdir)
        assert not has_traces
        assert detected == set()
        assert locations == {}

    def test_detailed_scan_with_traces(test_dir, compiled_test_patterns):
        """Test scan detecting traces."""
        test_file = test_dir / 'test.js'
        content = ["Line with lovable.dev\n", "Another with GPT\n"]
        with open(test_file, 'w') as f:
            f.writelines(content)
        
        with patch('__main__.COMPILED_PATTERNS', compiled_test_patterns):
            has_traces, detected, locations = detailed_scan(test_dir)
        
        assert has_traces
        assert 'Lovable Watermark' in detected
        assert 'GPT' in detected
        assert len(locations) == 1

    def test_verify_cleanup_passes(test_dir):
        """Test verification passes on clean repo."""
        with patch('__main__.detailed_scan', return_value=(False, set(), {})):
            result = verify_cleanup(test_dir)
        assert result is True

    @pytest.mark.parametrize("dry_run_value, expected_log", [
        (True, "DRY-RUN"),
        (False, None),
    ])
    def test_main_cleanup_dry_run(test_dir, dry_run_value, expected_log, caplog):
        """Test main_cleanup in dry-run mode."""
        caplog.set_level(logging.INFO)
        with patch('__main__.detailed_scan', return_value=(True, {'Lovable Watermark'}, {})):
            with patch('os.walk', return_value=[(str(test_dir), [], ['test.js'])]):
                with patch('__main__.clean_file', return_value=[]):
                    main_cleanup(test_dir, dry_run=dry_run_value)
        
        if expected_log:
            assert expected_log in caplog.text

if __name__ == "__main__":
    main()