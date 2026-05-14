from __future__ import annotations

import logging
import os.path
import sys
import time

logger = logging.getLogger(__name__)
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
    ".cache", ".thumbs",
})

CACHE_FILENAMES: frozenset[str] = frozenset({
    "thumbs.db", "desktop.ini", "cachefile.db",
})

DAYS_OLD: int = 180
LARGE_FILE_BYTES: int = 500 * 1024 * 1024


def classify_file(
    file_info: FileInfo,
    now: Optional[float] = None,
    size_threshold_mb: Optional[float] = None,
) -> list[JunkReason]:
    if now is None:
        now = time.time()

    reasons: list[JunkReason] = []

    try:
        ext: str = os.path.splitext(file_info.path)[1].lower()
    except (AttributeError, TypeError):
        ext = ""

    if ext in TEMP_EXTENSIONS:
        reasons.append(JunkReason.TEMP_EXTENSION)

    try:
        if (now - file_info.mtime) > DAYS_OLD * 86400:
            reasons.append(JunkReason.OLD_FILE)
    except (TypeError, ValueError, OSError):
        pass

    threshold = int(size_threshold_mb * 1024 * 1024) if size_threshold_mb is not None else LARGE_FILE_BYTES
    if file_info.size_bytes > threshold:
        reasons.append(JunkReason.LARGE_FILE)

    if file_info.size_bytes == 0:
        reasons.append(JunkReason.EMPTY_FILE)

    if ext in LOG_EXTENSIONS:
        reasons.append(JunkReason.LOG_FILE)

    fname_lower = os.path.basename(file_info.path).lower()
    if ext in CACHE_EXTENSIONS or fname_lower in CACHE_FILENAMES:
        reasons.append(JunkReason.CACHE_FILE)

    return reasons


def classify_files(
    files: list[FileInfo],
    now: Optional[float] = None,
    size_threshold_mb: Optional[float] = None,
) -> list[tuple[FileInfo, list[JunkReason]]]:
    if not files:
        return []

    resolved_now: float = now if now is not None else time.time()
    result: list[tuple[FileInfo, list[JunkReason]]] = []

    for file_info in files:
        try:
            reasons = classify_file(file_info, now=resolved_now, size_threshold_mb=size_threshold_mb)
            if reasons:
                result.append((file_info, reasons))
        except Exception as exc:
            logger.warning("classify_file failed for %s: %s", file_info.path, exc)
            continue

    return result
