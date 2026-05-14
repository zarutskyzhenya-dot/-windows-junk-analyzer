import os
import os.path
from datetime import datetime
from typing import Callable, Optional
from collections import defaultdict

from modules.rules import JunkReason, FileType, FILE_TYPE_PRIORITY, FILE_TYPE_LABEL, get_file_type, _FILE_TYPE_INDEX

REASON_PRIORITY = [
    JunkReason.TEMP_EXTENSION,
    JunkReason.LOG_FILE,
    JunkReason.CACHE_FILE,
    JunkReason.LARGE_FILE,
    JunkReason.EMPTY_FILE,
    JunkReason.OLD_FILE,
]

REASON_LABEL = {
    JunkReason.TEMP_EXTENSION: "TEMP",
    JunkReason.LOG_FILE:       "LOG",
    JunkReason.CACHE_FILE:     "CACHE",
    JunkReason.LARGE_FILE:     "LARGE",
    JunkReason.EMPTY_FILE:     "EMPTY",
    JunkReason.OLD_FILE:       "OLD",
}

REASON_MAP = {
    "temp":  JunkReason.TEMP_EXTENSION,
    "log":   JunkReason.LOG_FILE,
    "cache": JunkReason.CACHE_FILE,
    "large": JunkReason.LARGE_FILE,
    "empty": JunkReason.EMPTY_FILE,
    "old":   JunkReason.OLD_FILE,
}

_PRIORITY_INDEX = {r: i for i, r in enumerate(REASON_PRIORITY)}

REASON_SHORT = {
    JunkReason.OLD_FILE:       "стар",
    JunkReason.LARGE_FILE:     "бол",
    JunkReason.TEMP_EXTENSION: "врем",
    JunkReason.LOG_FILE:       "лог",
    JunkReason.CACHE_FILE:     "кэш",
    JunkReason.EMPTY_FILE:     "пуст",
}


def _format_compact_size(size_bytes: int) -> str:
    if size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f}KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f}MB"
    else:
        return f"{size_bytes / 1024 ** 3:.1f}GB"


def _primary_reason(reasons: list) -> JunkReason:
    return min(reasons, key=lambda r: _PRIORITY_INDEX.get(r, 999))


def sort_classified(classified: list) -> list:
    return sorted(classified, key=lambda item: (
        _FILE_TYPE_INDEX.get(get_file_type(item[0].path), 999),
        -item[0].size_bytes,
    ))


def format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.1f} GB"


def _format_total_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.2f} GB"


def build_report(
    classified: list,
    software_map: Optional[dict] = None,
    get_file_owner_fn: Optional[Callable] = None,
) -> str:
    separator = "=" * 40
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("Windows Junk Analyzer — Report")
    lines.append(f"Generated: {now_str}")
    lines.append(separator)

    total_files = len(classified)
    total_bytes = sum(fi.size_bytes for fi, _ in classified)

    lines.append(f"Total junk files: {total_files}")
    lines.append(f"Total size:       {_format_total_size(total_bytes)}")
    lines.append("")
    lines.append("--- By category ---")

    if total_files == 0:
        lines.append("(no categories)")
    else:
        group_counts: dict = {r: 0 for r in REASON_PRIORITY}
        group_bytes_map: dict = {r: 0 for r in REASON_PRIORITY}
        for file_info, reasons in classified:
            primary = _primary_reason(reasons)
            group_counts[primary] += 1
            group_bytes_map[primary] += file_info.size_bytes

        for reason in REASON_PRIORITY:
            if group_counts[reason] == 0:
                continue
            size_str = _format_total_size(group_bytes_map[reason])
            lines.append(f"{REASON_LABEL[reason]:<8} : {group_counts[reason]} files,  {size_str}")

    lines.append("")
    lines.append("--- File list ---")

    if total_files == 0:
        lines.append("No junk files found.")
    else:
        sorted_classified = sort_classified(classified)
        for idx, (file_info, reasons) in enumerate(sorted_classified, start=1):
            lines.append("")
            lines.append(f"#{idx} [{file_info.path}]")
            lines.append(f"  Size:   {format_size(file_info.size_bytes)}")
            lines.append(f"  Reason: {', '.join(r.value for r in reasons)}")

            if get_file_owner_fn is not None and software_map is not None:
                owner = get_file_owner_fn(file_info.path, software_map)
                if owner is not None:
                    lines.append(f"  Owner:  {owner}")

            try:
                mod_date = datetime.fromtimestamp(file_info.mtime).strftime("%Y-%m-%d")
            except (OSError, OverflowError, ValueError):
                mod_date = "unknown"
            lines.append(f"  Modified: {mod_date}")

    lines.append("")
    lines.append(separator)

    return "\n".join(lines)


_RST = "\033[0m"
_BLD = "\033[1m"
_CYN = "\033[36m"
_YLW = "\033[33m"
_RED = "\033[31m"
_GRY = "\033[90m"
_GRN = "\033[32m"


def build_report_pretty(
    classified: list,
    software_map: Optional[dict] = None,
    get_file_owner_fn: Optional[Callable] = None,
    show_old: bool = True,
) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_files = len(classified)
    total_bytes = sum(fi.size_bytes for fi, _ in classified)

    lines = []

    title = "Windows Junk Analyzer — Report"
    w = len(title) + 4
    lines.append(f"{_CYN}╔{'═' * w}╗{_RST}")
    lines.append(f"{_CYN}║{_BLD}  {title}  {_RST}{_CYN}║{_RST}")
    lines.append(f"{_CYN}╚{'═' * w}╝{_RST}")
    lines.append(f"  {_GRY}Generated: {now_str}{_RST}")
    lines.append("")

    size_color = _RED if total_bytes > 500 * 1024 * 1024 else _YLW
    lines.append(f"  Total junk files : {_BLD}{_YLW}{total_files}{_RST}")
    lines.append(f"  Total size       : {_BLD}{size_color}{_format_total_size(total_bytes)}{_RST}")
    lines.append("")

    if total_files == 0:
        lines.append(f"  {_GRN}No junk files found.{_RST}")
        return "\n".join(lines)

    ft_counts: dict = {ft: 0 for ft in FILE_TYPE_PRIORITY}
    ft_bytes:  dict = {ft: 0 for ft in FILE_TYPE_PRIORITY}
    for file_info, _ in classified:
        ft = get_file_type(file_info.path)
        ft_counts[ft] += 1
        ft_bytes[ft]  += file_info.size_bytes

    active_ft = [ft for ft in FILE_TYPE_PRIORITY if ft_counts[ft] > 0]

    lbl_w = max((len(FILE_TYPE_LABEL[ft]) for ft in active_ft), default=5)
    lbl_w = max(lbl_w, 8)
    num_w = max((len(str(ft_counts[ft])) for ft in active_ft), default=5)
    num_w = max(num_w, 5)
    sz_w  = 10

    def _row(cat: str, num: str, sz: str, header: bool = False) -> str:
        cat_p = f"{cat:<{lbl_w}}"
        num_p = f"{num:>{num_w}}"
        sz_p  = f"{sz:>{sz_w}}"
        if header:
            return f"  │ {_BLD}{cat_p}{_RST} │ {_BLD}{num_p}{_RST} │ {_BLD}{sz_p}{_RST} │"
        return f"  │ {cat_p} │ {num_p} │ {sz_p} │"

    top    = f"  ┌{'─' * (lbl_w + 2)}┬{'─' * (num_w + 2)}┬{'─' * (sz_w + 2)}┐"
    mid    = f"  ├{'─' * (lbl_w + 2)}┼{'─' * (num_w + 2)}┼{'─' * (sz_w + 2)}┤"
    bottom = f"  └{'─' * (lbl_w + 2)}┴{'─' * (num_w + 2)}┴{'─' * (sz_w + 2)}┘"

    lines.append(top)
    lines.append(_row("Тип", "Файлов", "Размер", header=True))
    lines.append(mid)
    for ft in active_ft:
        lines.append(_row(FILE_TYPE_LABEL[ft], str(ft_counts[ft]),
                          _format_total_size(ft_bytes[ft])))
    lines.append(bottom)
    lines.append("")

    sorted_classified = sort_classified(classified)
    current_group = None
    idx = 0

    for file_info, reasons in sorted_classified:
        ft = get_file_type(file_info.path)

        if ft != current_group:
            current_group = ft
            label = FILE_TYPE_LABEL[ft]
            count = ft_counts[ft]
            size  = _format_total_size(ft_bytes[ft])
            lines.append(f"  {_CYN}━━━ {label} — {count} файлов — {size} ━━━{_RST}")
            lines.append("")

        idx += 1
        fname = os.path.basename(file_info.path)
        size_str = _format_compact_size(file_info.size_bytes)
        reasons_str = "/".join(REASON_SHORT.get(r, r.value) for r in reasons)
        try:
            mod_date = datetime.fromtimestamp(file_info.mtime).strftime("%Y-%m-%d")
        except (OSError, OverflowError, ValueError):
            mod_date = "unknown"
        ft_label = FILE_TYPE_LABEL[ft].lower()

        owner_str = ""
        if get_file_owner_fn is not None and software_map is not None:
            try:
                owner = get_file_owner_fn(file_info.path, software_map)
                if owner:
                    owner_str = f"  {_GRY}[{owner}]{_RST}"
            except Exception:
                pass

        lines.append(f"  {_BLD}#{idx}  ▶ {fname}{_RST}")
        lines.append(f"      {_YLW}{size_str}{_RST}  {_RED}[{reasons_str}]{_RST}  {_GRY}{mod_date}  ({ft_label}){_RST}{owner_str}")
        lines.append(f"      {_GRY}{file_info.path}{_RST}")
        lines.append("")

    return "\n".join(lines)


def save_report(text: str, output_path: str) -> bool:
    try:
        parent_dir = os.path.dirname(output_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return True
    except OSError:
        return False
