import argparse
import logging
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from send2trash import send2trash

from modules.protection import is_protected_path, is_system_file
from modules.software_map import build_software_map, get_file_owner
from modules.process_check import get_open_files, is_file_in_use
from modules.scanner import scan_directories
from modules.rules import classify_files
from modules.report import build_report, build_report_pretty, save_report, format_size


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
            logger.warning("Scan path does not exist and will be skipped: %s", path)
    return paths


def collect_open_files():
    print("Collecting open files...")
    try:
        open_files = get_open_files()
        return open_files if open_files is not None else set()
    except Exception as exc:
        logger.warning("Could not collect open files (%s: %s). In-use detection disabled.", type(exc).__name__, exc)
        return set()


def collect_software_map(db_path):
    print("Building software map...")
    try:
        software_map = build_software_map(db_path)
        return software_map if software_map is not None else {}
    except Exception as exc:
        logger.warning("Could not build software map (%s: %s). No ownership info.", type(exc).__name__, exc)
        return {}


def ask_threshold() -> float:
    print("  Мінімальний розмір 'великого файлу' (МБ) [500]: ", end="")
    try:
        line = input().strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not line:
        return 500.0
    try:
        val = float(line)
        if val <= 0:
            raise ValueError
        print(f"  \033[32m[+] Поріг: {val:.0f} МБ\033[0m")
        return val
    except ValueError:
        print("  \033[33m[!] Невірне значення, використовую 500 МБ\033[0m")
        return 500.0


def _interactive_delete(classified: list) -> None:
    if not classified:
        return
    sorted_files = sorted(classified, key=lambda x: x[0].size_bytes, reverse=True)
    print("  \033[90m─────────────────────────────────────────────\033[0m")
    print("  Видалити файли? \033[1m[A]\033[0mll  \033[1m[N]\033[0mone  або номери через кому \033[1m(1,3)\033[0m: ", end="")
    try:
        answer = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if not answer or answer in ("n", "none"):
        print("  Нічого не видалено.")
        return

    if answer in ("a", "all"):
        targets = list(range(len(sorted_files)))
    else:
        try:
            targets = []
            n = len(sorted_files)
            for token in answer.split(","):
                token = token.strip()
                if "-" in token:
                    a, b = token.split("-", 1)
                    a, b = int(a), int(b)
                    if a > b:
                        print(f"  \033[33m[!] Невірний діапазон {a}-{b}: початок більше кінця.\033[0m")
                        return
                    targets.extend(range(a - 1, b))
                else:
                    targets.append(int(token) - 1)
            invalid = [i + 1 for i in targets if not (0 <= i < n)]
            if invalid:
                print(f"  \033[33m[!] Номери поза списком: {', '.join(map(str, invalid))}. Макс: {n}.\033[0m")
                return
            targets = list(dict.fromkeys(targets))
        except ValueError:
            print("  \033[31m[!] Невірний формат. Приклад: 1,3 або 2-5 або 1,3-7\033[0m")
            return

    if not targets:
        print("  Нічого не видалено.")
        return

    print()
    for i in targets:
        fi = sorted_files[i][0]
        print(f"    \033[33m{i+1}. {fi.path}  ({format_size(fi.size_bytes)})\033[0m")
    print()
    print(f"  \033[31mФайли будуть видалені ({len(targets)} шт.). Ви впевнені? [д/н]:\033[0m ", end="")
    try:
        confirm = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if confirm not in ("д", "y"):
        print("  Скасовано.")
        return

    deleted = 0
    for i in targets:
        path = sorted_files[i][0].path
        fname = os.path.basename(path)
        try:
            if not os.path.exists(path):
                print(f"  \033[33m[SKIP]\033[0m {fname}: файл вже не існує")
                continue
            if is_protected_path(path) or is_system_file(path):
                print(f"  \033[31m[BLOCK]\033[0m {fname}: захищений файл")
                continue
            send2trash(path)
            print(f"  \033[32m[OK]\033[0m {fname}")
            deleted += 1
        except Exception as exc:
            print(f"  \033[31m[ERR]\033[0m {fname}: {exc}")

    print(f"\n  Видалено: {deleted} файлів")


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
        if len(expanded) == 2 and expanded[1] == ':':
            expanded = expanded + os.sep
        if not os.path.isdir(expanded):
            print(f"  \033[31m[!] Папка не найдена: {expanded}\033[0m")
        else:
            paths.append(expanded)
            print(f"  \033[32m[+] Добавлено\033[0m")
    print()
    return paths


logger = logging.getLogger(__name__)


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = parse_args(argv)

    db_path = resolve_db_path(args.db)
    min_size_bytes = int(args.min_size * 1024 * 1024)

    if args.scan:
        scan_paths = [os.path.expandvars(os.path.expanduser(p)) for p in args.scan]
        validate_scan_paths(scan_paths)
        size_threshold_mb = args.min_size if args.min_size else None
    else:
        size_threshold_mb = ask_threshold()
        scan_paths = ask_scan_paths()

    open_files = collect_open_files()

    software_map = {}
    if not args.no_software_map:
        software_map = collect_software_map(db_path)

    print("Scanning directories...")
    is_protected = lambda p: is_protected_path(p) or is_system_file(p)
    is_in_use = lambda p: is_file_in_use(p, open_files)

    exclude_paths = {os.path.normcase(os.path.abspath(db_path))}
    try:
        files = scan_directories(roots=scan_paths, is_protected=is_protected,
                                 is_in_use=is_in_use, min_size_bytes=min_size_bytes,
                                 follow_junctions=args.follow_junctions,
                                 exclude_paths=exclude_paths) or []
    except Exception as exc:
        logger.error("Scan failed (%s: %s).", type(exc).__name__, exc)
        sys.exit(1)

    print(f"Found {len(files)} files. Classifying...")
    try:
        classified = classify_files(files, size_threshold_mb=size_threshold_mb) or []
    except Exception as exc:
        logger.error("Classification failed (%s: %s).", type(exc).__name__, exc)
        sys.exit(1)

    print(f"Junk files: {len(classified)}. Building report...")
    get_file_owner_fn = get_file_owner if software_map else None

    try:
        report_text = build_report(classified, software_map=software_map or None,
                                   get_file_owner_fn=get_file_owner_fn) or ""
    except Exception as exc:
        logger.error("Report generation failed (%s: %s).", type(exc).__name__, exc)
        sys.exit(1)

    if args.output:
        if save_report(report_text, args.output):
            pretty = build_report_pretty(classified, software_map=software_map or None,
                                         get_file_owner_fn=get_file_owner_fn)
            print(pretty)
            print(f"\nReport saved to {args.output}")
        else:
            logger.error("Could not save report to '%s'.", args.output)
            sys.exit(1)
    else:
        pretty = build_report_pretty(classified, software_map=software_map or None,
                                     get_file_owner_fn=get_file_owner_fn)
        print(pretty)
        _interactive_delete(classified)


if __name__ == "__main__":
    main()
    if getattr(sys, "frozen", False):
        input("\nНажми Enter чтобы закрыть...")
