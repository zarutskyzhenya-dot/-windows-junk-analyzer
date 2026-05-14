from __future__ import annotations

import os.path
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional


@dataclass
class FileInfo:
    path: str
    size_bytes: int
    mtime: float


class JunkReason(Enum):
    TEMP_EXTENSION = "temp_extension"
    OLD_FILE       = "old_file"
    LARGE_FILE     = "large_file"
    EMPTY_FILE     = "empty_file"
    LOG_FILE       = "log_file"
    CACHE_FILE     = "cache_file"


TEMP_EXTENSIONS: frozenset[str] = frozenset({
    ".tmp", ".temp", ".bak", ".old", ".orig", ".~",
    ".swp", ".swo", ".dmp", ".gid", ".chk",
})

LOG_EXTENSIONS: frozenset[str] = frozenset({
    ".log", ".log1", ".log2", ".etl",
})

CACHE_EXTENSIONS: frozenset[str] = frozenset({
    ".cache", ".thumbs", ".db",
})

DAYS_OLD: int = 180
LARGE_FILE_BYTES: int = 500 * 1024 * 1024


def classify_file(
    file_info: FileInfo,
    now: Optional[float] = None,
) -> list[JunkReason]:
    try:
        if now is None:
            now = time.time()

        reasons: list[JunkReason] = []

        try:
            ext: str = os.path.splitext(file_info.path)[1].lower()
        except Exception:
            ext = ""

        if ext in TEMP_EXTENSIONS:
            reasons.append(JunkReason.TEMP_EXTENSION)

        try:
            if (now - file_info.mtime) > DAYS_OLD * 86400:
                reasons.append(JunkReason.OLD_FILE)
        except Exception:
            pass

        try:
            if file_info.size_bytes > LARGE_FILE_BYTES:
                reasons.append(JunkReason.LARGE_FILE)
        except Exception:
            pass

        try:
            if file_info.size_bytes == 0:
                reasons.append(JunkReason.EMPTY_FILE)
        except Exception:
            pass

        if ext in LOG_EXTENSIONS:
            reasons.append(JunkReason.LOG_FILE)

        if ext in CACHE_EXTENSIONS:
            reasons.append(JunkReason.CACHE_FILE)

        return reasons

    except Exception:
        return []


def classify_files(
    files: list[FileInfo],
    now: Optional[float] = None,
) -> list[tuple[FileInfo, list[JunkReason]]]:
    if not files:
        return []

    resolved_now: float = now if now is not None else time.time()
    result: list[tuple[FileInfo, list[JunkReason]]] = []

    for file_info in files:
        try:
            reasons = classify_file(file_info, now=resolved_now)
            if reasons:
                result.append((file_info, reasons))
        except Exception:
            continue

    return result
