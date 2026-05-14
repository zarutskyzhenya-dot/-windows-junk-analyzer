import os
import os.path
from datetime import datetime
from typing import Callable, Optional
from collections import defaultdict


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
        category_counts: dict = defaultdict(int)
        category_bytes: dict = defaultdict(int)

        for file_info, reasons in classified:
            for reason in reasons:
                category_counts[reason] += 1
                category_bytes[reason] += file_info.size_bytes

        seen_reasons = []
        seen_set = set()
        for _, reasons in classified:
            for reason in reasons:
                if reason not in seen_set:
                    seen_reasons.append(reason)
                    seen_set.add(reason)

        for reason in seen_reasons:
            count = category_counts[reason]
            size_str = _format_total_size(category_bytes[reason])
            lines.append(f"{reason.value.upper():<16} : {count} files,  {size_str}")

    lines.append("")
    lines.append("--- File list ---")

    if total_files == 0:
        lines.append("No junk files found.")
    else:
        sorted_classified = sorted(classified, key=lambda item: item[0].size_bytes, reverse=True)

        for file_info, reasons in sorted_classified:
            lines.append("")
            lines.append(f"[{file_info.path}]")
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
) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_files = len(classified)
    total_bytes = sum(fi.size_bytes for fi, _ in classified)

    lines = []

    # Header
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

    # Category table
    if total_files > 0:
        category_counts: dict = defaultdict(int)
        category_bytes_map: dict = defaultdict(int)
        seen_reasons: list = []
        seen_set: set = set()
        for file_info, reasons in classified:
            for reason in reasons:
                category_counts[reason] += 1
                category_bytes_map[reason] += file_info.size_bytes
                if reason not in seen_set:
                    seen_reasons.append(reason)
                    seen_set.add(reason)

        cat_w = max((len(r.value) for r in seen_reasons), default=8)
        cat_w = max(cat_w, 8)
        num_w = 6
        sz_w = 10

        def _row(cat: str, num: str, sz: str, header: bool = False) -> str:
            cat_p = f"{cat:<{cat_w}}"
            num_p = f"{num:>{num_w}}"
            sz_p  = f"{sz:>{sz_w}}"
            if header:
                return f"│ {_BLD}{cat_p}{_RST} │ {_BLD}{num_p}{_RST} │ {_BLD}{sz_p}{_RST} │"
            return f"│ {cat_p} │ {num_p} │ {sz_p} │"

        top    = f"┌{'─' * (cat_w + 2)}┬{'─' * (num_w + 2)}┬{'─' * (sz_w + 2)}┐"
        mid    = f"├{'─' * (cat_w + 2)}┼{'─' * (num_w + 2)}┼{'─' * (sz_w + 2)}┤"
        bottom = f"└{'─' * (cat_w + 2)}┴{'─' * (num_w + 2)}┴{'─' * (sz_w + 2)}┘"

        lines.append(f"  {_CYN}By category{_RST}")
        lines.append(top)
        lines.append(_row("Category", "Files", "Size", header=True))
        lines.append(mid)
        for reason in seen_reasons:
            lines.append(_row(reason.value, str(category_counts[reason]),
                              _format_total_size(category_bytes_map[reason])))
        lines.append(bottom)
        lines.append("")

    # File list
    lines.append(f"  {_CYN}File list{_RST}  {_GRY}(largest first){_RST}")
    lines.append("")

    if total_files == 0:
        lines.append(f"  {_GRN}No junk files found.{_RST}")
    else:
        sorted_classified = sorted(classified, key=lambda item: item[0].size_bytes, reverse=True)
        for file_info, reasons in sorted_classified:
            fname = os.path.basename(file_info.path)
            lines.append(f"  {_BLD}▶ {fname}{_RST}")
            lines.append(f"    {_GRY}Path    :{_RST} {file_info.path}")
            lines.append(f"    {_GRY}Size    :{_RST} {_YLW}{format_size(file_info.size_bytes)}{_RST}")
            reasons_str = ", ".join(f"{_RED}{r.value}{_RST}" for r in reasons)
            lines.append(f"    {_GRY}Reason  :{_RST} {reasons_str}")

            if get_file_owner_fn is not None and software_map is not None:
                try:
                    owner = get_file_owner_fn(file_info.path, software_map)
                    if owner:
                        lines.append(f"    {_GRY}Owner   :{_RST} {owner}")
                except Exception:
                    pass

            try:
                mod_date = datetime.fromtimestamp(file_info.mtime).strftime("%Y-%m-%d")
            except (OSError, OverflowError, ValueError):
                mod_date = "unknown"
            lines.append(f"    {_GRY}Modified:{_RST} {mod_date}")
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
