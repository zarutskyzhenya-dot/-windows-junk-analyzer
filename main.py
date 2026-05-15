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
from modules.rules import classify_files, DAYS_OLD
from modules.report import (build_report, build_report_pretty, save_report,
                            format_size, sort_classified, REASON_MAP, _primary_reason)


STRINGS = {
    "ru": {
        "days_prompt":     "Старые файлы: старше чем (дней)",
        "size_prompt":     "Минимальный размер файлов (МБ)",
        "bad_value":       "Неверное значение, использую",
        "enter_folders":   "Введите папки для сканирования.",
        "folders_hint":    "Каждая папка — на новой строке. Пустая строка — старт.",
        "folder_prompt":   "Папка",
        "need_folder":     "Нужна хотя бы одна папка.",
        "not_found":       "Папка не найдена",
        "added":           "[+] Добавлено",
        "delete_prompt":   "Удалить файлы? \033[1m[A]\033[0mll  \033[1m[N]\033[0mone  или номера через запятую \033[1m(1,3)\033[0m",
        "nothing_deleted": "Ничего не удалено.",
        "bad_range":       "Неверный диапазон {a}-{b}: начало больше конца.",
        "out_of_range":    "Номера вне списка: {inv}. Макс: {n}.",
        "bad_format":      "Неверный формат. Пример: 1,3 или 2-5 или 1,3-7",
        "confirm_delete":  "Файлы будут удалены ({n} шт.). Вы уверены? [д/н]",
        "confirm_yes":     ("д", "y"),
        "cancelled":       "Отменено.",
        "skip_missing":    "файл уже не существует",
        "blocked":         "защищённый файл",
        "deleted_count":   "Удалено: {n} файлов",
        "collecting":      "Collecting open files...",
        "building_map":    "Building software map...",
        "scanning":        "Scanning directories...",
        "found_files":     "Found {n} files. Classifying...",
        "junk_files":      "Junk files: {n}. Building report...",
        "report_saved":    "Report saved to {path}",
        "press_enter":     "Нажмите Enter для закрытия...",
    },
    "en": {
        "days_prompt":     "Old files: older than (days)",
        "size_prompt":     "Minimum file size (MB)",
        "bad_value":       "Invalid value, using",
        "enter_folders":   "Enter folders to scan.",
        "folders_hint":    "One folder per line. Empty line — start.",
        "folder_prompt":   "Folder",
        "need_folder":     "At least one folder required.",
        "not_found":       "Folder not found",
        "added":           "[+] Added",
        "delete_prompt":   "Delete files? \033[1m[A]\033[0mll  \033[1m[N]\033[0mone  or numbers separated by comma \033[1m(1,3)\033[0m",
        "nothing_deleted": "Nothing deleted.",
        "bad_range":       "Invalid range {a}-{b}: start > end.",
        "out_of_range":    "Numbers out of range: {inv}. Max: {n}.",
        "bad_format":      "Invalid format. Example: 1,3 or 2-5 or 1,3-7",
        "confirm_delete":  "Files will be deleted ({n} pcs). Are you sure? [y/n]",
        "confirm_yes":     ("y",),
        "cancelled":       "Cancelled.",
        "skip_missing":    "file no longer exists",
        "blocked":         "protected file",
        "deleted_count":   "Deleted: {n} files",
        "collecting":      "Collecting open files...",
        "building_map":    "Building software map...",
        "scanning":        "Scanning directories...",
        "found_files":     "Found {n} files. Classifying...",
        "junk_files":      "Junk files: {n}. Building report...",
        "report_saved":    "Report saved to {path}",
        "press_enter":     "Press Enter to close...",
    },
}


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
    parser.add_argument("--days", metavar="N", type=int, default=None, dest="days",
                        help=f"Files older than N days are 'old' (default: {DAYS_OLD}).")
    parser.add_argument("--reason", metavar="CATEGORIES", default=None, dest="reason",
                        help="Show only specified categories: temp,log,cache,large,empty,old (comma-separated).")
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


def _ask_int(prompt: str, default: int, S: dict) -> int:
    print(f"  {prompt} [{default}]: ", end="")
    try:
        line = input().strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not line:
        return default
    try:
        val = int(line)
        if val <= 0:
            raise ValueError
        return val
    except ValueError:
        print(f"  \033[33m[!] {S['bad_value']} {default}\033[0m")
        return default


def _ask_float(prompt: str, default: float, S: dict) -> float:
    print(f"  {prompt} [{default:.0f}]: ", end="")
    try:
        line = input().strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not line:
        return default
    try:
        val = float(line)
        if val <= 0:
            raise ValueError
        return val
    except ValueError:
        print(f"  \033[33m[!] {S['bad_value']} {default:.0f}\033[0m")
        return default


def _interactive_delete(classified: list, S: dict) -> None:
    if not classified:
        return
    sorted_files = sort_classified(classified)
    print("  \033[90m─────────────────────────────────────────────\033[0m")
    print(f"  {S['delete_prompt']}: ", end="")
    try:
        answer = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if not answer or answer in ("n", "none"):
        print(f"  {S['nothing_deleted']}")
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
                        print(f"  \033[33m[!] {S['bad_range'].format(a=a, b=b)}\033[0m")
                        return
                    targets.extend(range(a - 1, b))
                else:
                    targets.append(int(token) - 1)
            invalid = [i + 1 for i in targets if not (0 <= i < n)]
            if invalid:
                print(f"  \033[33m[!] {S['out_of_range'].format(inv=', '.join(map(str, invalid)), n=n)}\033[0m")
                return
            targets = list(dict.fromkeys(targets))
        except ValueError:
            print(f"  \033[31m[!] {S['bad_format']}\033[0m")
            return

    if not targets:
        print(f"  {S['nothing_deleted']}")
        return

    print()
    for i in targets:
        fi = sorted_files[i][0]
        print(f"    \033[33m{i+1}. {fi.path}  ({format_size(fi.size_bytes)})\033[0m")
    print()
    print(f"  \033[31m{S['confirm_delete'].format(n=len(targets))}:\033[0m ", end="")
    try:
        confirm = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if confirm not in S["confirm_yes"]:
        print(f"  {S['cancelled']}")
        return

    deleted = 0
    for i in targets:
        path = sorted_files[i][0].path
        fname = os.path.basename(path)
        try:
            if not os.path.exists(path):
                print(f"  \033[33m[SKIP]\033[0m {fname}: {S['skip_missing']}")
                continue
            if is_protected_path(path) or is_system_file(path):
                print(f"  \033[31m[BLOCK]\033[0m {fname}: {S['blocked']}")
                continue
            send2trash(path)
            print(f"  \033[32m[OK]\033[0m {fname}")
            deleted += 1
        except Exception as exc:
            print(f"  \033[31m[ERR]\033[0m {fname}: {exc}")

    print(f"\n  {S['deleted_count'].format(n=deleted)}")


def interactive_setup() -> tuple:
    _W = 38
    _title = "Windows Junk Analyzer — Setup"
    print(f"\033[36m╔{'═' * _W}╗\033[0m")
    print(f"\033[36m║\033[0m\033[1m   {_title}{' ' * (_W - 3 - len(_title))}\033[0m\033[36m║\033[0m")
    print(f"\033[36m╚{'═' * _W}╝\033[0m")
    print()

    print("  Language / Язык [ru/en]: ", end="")
    try:
        lang_input = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    lang = "en" if lang_input == "en" else "ru"
    S = STRINGS[lang]
    print()

    days_old = _ask_int(S["days_prompt"], DAYS_OLD, S)
    size_mb  = _ask_float(S["size_prompt"], 500.0, S)
    print()
    print(f"  \033[90m{'─' * (_W + 2)}\033[0m")
    print()
    print(f"  {S['enter_folders']}")
    print(f"  \033[90m{S['folders_hint']}\033[0m")
    print()

    paths = []
    while True:
        try:
            line = input(f"  {S['folder_prompt']}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        if not line:
            if not paths:
                print(f"  \033[33m{S['need_folder']}\033[0m")
                continue
            break
        expanded = os.path.expandvars(os.path.expanduser(line))
        if len(expanded) == 2 and expanded[1] == ':':
            expanded = expanded + os.sep
        if not os.path.isdir(expanded):
            print(f"  \033[31m[!] {S['not_found']}: {expanded}\033[0m")
        else:
            paths.append(expanded)
            print(f"  \033[32m{S['added']}\033[0m")
    print()
    return days_old, size_mb, paths, lang


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
        days_old = args.days
        lang = "en"
    else:
        days_old, size_threshold_mb, scan_paths, lang = interactive_setup()
        min_size_bytes = int(size_threshold_mb * 1024 * 1024)

    S = STRINGS[lang]

    open_files = collect_open_files()

    software_map = {}
    if not args.no_software_map:
        software_map = collect_software_map(db_path)

    print(S["scanning"])
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

    print(S["found_files"].format(n=len(files)))
    try:
        classified = classify_files(files, size_threshold_mb=size_threshold_mb,
                                    days_old=days_old) or []
    except Exception as exc:
        logger.error("Classification failed (%s: %s).", type(exc).__name__, exc)
        sys.exit(1)

    if args.reason:
        allowed = {REASON_MAP[n.strip().lower()] for n in args.reason.split(",")
                   if n.strip().lower() in REASON_MAP}
        if allowed:
            classified = [(fi, r) for fi, r in classified if _primary_reason(r) in allowed]

    print(S["junk_files"].format(n=len(classified)))
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
                                         get_file_owner_fn=get_file_owner_fn, lang=lang)
            print(pretty)
            print(f"\n{S['report_saved'].format(path=args.output)}")
        else:
            logger.error("Could not save report to '%s'.", args.output)
            sys.exit(1)
    else:
        pretty = build_report_pretty(classified, software_map=software_map or None,
                                     get_file_owner_fn=get_file_owner_fn, lang=lang)
        print(pretty)
        _interactive_delete(classified, S)

    if getattr(sys, "frozen", False):
        try:
            input(f"\n{S['press_enter']}")
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    main()
