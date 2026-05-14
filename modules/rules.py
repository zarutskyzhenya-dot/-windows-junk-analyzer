from __future__ import annotations

import logging
import os.path
import sys
import time

logger = logging.getLogger(__name__)
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class FileType(Enum):
    PHOTO    = "photo"
    VIDEO    = "video"
    MUSIC    = "music"
    PROGRAMS = "programs"
    FILES_1C = "1c"
    ARCHIVE  = "archive"
    OTHER    = "other"


_PHOTO_EXT: frozenset[str] = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
    ".raw", ".heic", ".heif", ".webp", ".svg", ".ico",
})
_VIDEO_EXT: frozenset[str] = frozenset({
    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".m4v",
    ".mpg", ".mpeg", ".ts", ".3gp", ".webm", ".vob", ".mts", ".m2ts",
})
_MUSIC_EXT: frozenset[str] = frozenset({
    ".mp3", ".flac", ".wav", ".aac", ".ogg", ".wma", ".m4a", ".opus", ".ape",
})
_PROGRAMS_EXT: frozenset[str] = frozenset({
    ".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".reg",
    ".inf", ".sys", ".drv", ".cab", ".iso", ".pyd", ".so",
    ".dmg", ".pkg", ".deb", ".rpm", ".appimage",
})
_1C_EXT: frozenset[str] = frozenset({
    ".1cd", ".dt", ".cf", ".cfl", ".epf", ".erf", ".dbf", ".cdx", ".idx",
})
_ARCHIVE_EXT: frozenset[str] = frozenset({
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz",
    ".tar.gz", ".tar.bz2", ".z", ".lz", ".lzma", ".zst",
})

FILE_TYPE_PRIORITY = [
    FileType.PHOTO,
    FileType.VIDEO,
    FileType.MUSIC,
    FileType.PROGRAMS,
    FileType.FILES_1C,
    FileType.ARCHIVE,
    FileType.OTHER,
]

FILE_TYPE_LABEL = {
    FileType.PHOTO:    "ФОТО",
    FileType.VIDEO:    "ВИДЕО",
    FileType.MUSIC:    "МУЗЫКА",
    FileType.PROGRAMS: "ПРОГРАММЫ",
    FileType.FILES_1C: "1С",
    FileType.ARCHIVE:  "АРХИВ",
    FileType.OTHER:    "ДРУГОЕ",
}

_FILE_TYPE_INDEX = {ft: i for i, ft in enumerate(FILE_TYPE_PRIORITY)}


def get_file_type(path: str) -> FileType:
    try:
        ext = os.path.splitext(path)[1].lower()
    except (AttributeError, TypeError):
        return FileType.OTHER
    if ext in _PHOTO_EXT:
        return FileType.PHOTO
    if ext in _VIDEO_EXT:
        return FileType.VIDEO
    if ext in _MUSIC_EXT:
        return FileType.MUSIC
    if ext in _PROGRAMS_EXT:
        return FileType.PROGRAMS
    if ext in _1C_EXT:
        return FileType.FILES_1C
    if ext in _ARCHIVE_EXT:
        return FileType.ARCHIVE
    return FileType.OTHER


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
    days_old: Optional[int] = None,
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

    _days = days_old if days_old is not None else DAYS_OLD
    try:
        if (now - file_info.mtime) > _days * 86400:
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
    days_old: Optional[int] = None,
) -> list[tuple[FileInfo, list[JunkReason]]]:
    if not files:
        return []

    resolved_now: float = now if now is not None else time.time()
    result: list[tuple[FileInfo, list[JunkReason]]] = []

    for file_info in files:
        try:
            reasons = classify_file(file_info, now=resolved_now,
                                    size_threshold_mb=size_threshold_mb, days_old=days_old)
            if reasons:
                result.append((file_info, reasons))
        except Exception as exc:
            logger.warning("classify_file failed for %s: %s", file_info.path, exc)
            continue

    return result
