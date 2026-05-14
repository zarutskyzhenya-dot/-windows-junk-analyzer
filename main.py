import argparse
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from modules.protection import is_protected_path, is_system_file
from modules.software_map import build_software_map, get_file_owner
from modules.process_check import get_open_files, is_file_in_use
from modules.scanner import scan_directories
from modules.rules import classify_files
from modules.report import build_report, build_report_pretty, save_report


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Windows Junk Analyzer - Scans directories for junk files and produces a report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            '  python main.py --scan "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp"\n'
            '  python main.py --scan "C:\\Temp" "C:\\Windows\\Temp" --output report.txt\n'
            '  python main.py --scan "C:\\Temp" --min-size 1 --no-software-map\n'
        ),
    )
    parser.add_argument("--scan", metavar="PATH", nargs="+", required=False, default=None,
                        help="One or more directories to scan. If omitted, asked interactively.")
    parser.add_argument("--output", metavar="FILE", default=None,
                        help="Save report to FILE (if omitted, report is printed to stdout).")
    parser.add_argument("--min-size", metavar="MB", type=float, default=0.0, dest="min_size",
                        help="Skip files smaller than MB megabytes (default: 0).")
    parser.add_argument("--db", metavar="PATH", default=None, dest="db",
                        help="SQLite database path for software map cache (default: junk_analyzer.db next to main.py).")
    parser.add_argument("--no-software-map", action="store_true", default=False, dest="no_software_map",
                        help="Skip registry scan for software ownership info (faster).")
    parser.add_argument("--follow-junctions", action="store_true", default=False, dest="follow_junctions",
                        help="Follow junction points (by default skipped to avoid cross-drive duplicates).")
    return parser.parse_args(argv)


def resolve_db_path(db_arg):
    if db_arg is not None:
        return db_arg
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "junk_analyzer.db")


def validate_scan_paths(paths):
    for path in paths:
        if not os.path.exists(path):
            print(f"[WARNING] Scan path does not exist and will be skipped: {path}", file=sys.stderr)
    return paths


def collect_open_files():
    print("Collecting open files...")
    try:
        open_files = get_open_files()
        return open_files if open_files is not None else set()
    except Exception as exc:
        print(f"[WARNING] Could not collect open files ({type(exc).__name__}: {exc}). In-use detection disabled.",
              file=sys.stderr)
        return set()


def collect_software_map(db_path):
    print("Building software map...")
    try:
        software_map = build_software_map(db_path)
        return software_map if software_map is not None else {}
    except Exception as exc:
        print(f"[WARNING] Could not build software map ({type(exc).__name__}: {exc}). No ownership info.",
              file=sys.stderr)
        return {}


def ask_scan_paths() -> list[str]:
    print("\033[36m╔══════════════════════════════════════╗\033[0m")
    print("\033[36m║\033[0m\033[1m   Windows Junk Analyzer — Setup    \033[0m\033[36m  ║\033[0m")
    print("\033[36m╚══════════════════════════════════════╝\033[0m")
    print()
    print("  Введи папки для сканирования.")
    print("  \033[90mКаждая папка — на новой строке. Пустая строка — старт.\033[0m")
    print()
    paths = []
    while True:
        try:
            line = input("  Папка: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not line:
            if not paths:
                print("  \033[33mНужна хотя бы одна папка.\033[0m")
                continue
            break
        expanded = os.path.expandvars(os.path.expanduser(line))
        if not os.path.isdir(expanded):
            print(f"  \033[31m[!] Папка не найдена: {expanded}\033[0m")
        else:
            paths.append(expanded)
            print(f"  \033[32m[+] Добавлено\033[0m")
    print()
    return paths


def main(argv=None):
    args = parse_args(argv)

    db_path = resolve_db_path(args.db)
    min_size_bytes = int(args.min_size * 1024 * 1024)

    if args.scan:
        scan_paths = [os.path.expandvars(os.path.expanduser(p)) for p in args.scan]
        validate_scan_paths(scan_paths)
    else:
        scan_paths = ask_scan_paths()

    open_files = collect_open_files()

    software_map = {}
    if not args.no_software_map:
        software_map = collect_software_map(db_path)

    print("Scanning directories...")
    is_protected = lambda p: is_protected_path(p) or is_system_file(p)
    is_in_use = lambda p: is_file_in_use(p, open_files)

    try:
        files = scan_directories(roots=scan_paths, is_protected=is_protected,
                                 is_in_use=is_in_use, min_size_bytes=min_size_bytes,
                                 follow_junctions=args.follow_junctions) or []
    except Exception as exc:
        print(f"[ERROR] Scan failed ({type(exc).__name__}: {exc}).", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(files)} files. Classifying...")
    try:
        classified = classify_files(files) or []
    except Exception as exc:
        print(f"[ERROR] Classification failed ({type(exc).__name__}: {exc}).", file=sys.stderr)
        sys.exit(1)

    print(f"Junk files: {len(classified)}. Building report...")
    get_file_owner_fn = get_file_owner if software_map else None

    try:
        report_text = build_report(classified, software_map=software_map or None,
                                   get_file_owner_fn=get_file_owner_fn) or ""
    except Exception as exc:
        print(f"[ERROR] Report generation failed ({type(exc).__name__}: {exc}).", file=sys.stderr)
        sys.exit(1)

    if args.output:
        if save_report(report_text, args.output):
            pretty = build_report_pretty(classified, software_map=software_map or None,
                                         get_file_owner_fn=get_file_owner_fn)
            print(pretty)
            print(f"\nReport saved to {args.output}")
        else:
            print(f"[ERROR] Could not save report to '{args.output}'.", file=sys.stderr)
            sys.exit(1)
    else:
        pretty = build_report_pretty(classified, software_map=software_map or None,
                                     get_file_owner_fn=get_file_owner_fn)
        print(pretty)


if __name__ == "__main__":
    main()
