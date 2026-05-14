import logging
import os
import os.path
import sys
from dataclasses import dataclass
from typing import Callable, FrozenSet, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class FileInfo:
    path: str
    size_bytes: int
    mtime: float


def _is_junction(path: str) -> bool:
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    try:
        st = os.lstat(path)
        attrs = getattr(st, "st_file_attributes", None)
        if attrs is not None:
            return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        pass
    return False


def _dir_key(path: str) -> object:
    try:
        st = os.stat(path)
        if st.st_ino != 0:
            return (st.st_dev, st.st_ino)
    except OSError:
        pass
    try:
        return os.path.realpath(path)
    except OSError:
        return path


def scan_directory(
    root: str,
    is_protected: Callable[[str], bool],
    is_in_use: Callable[[str], bool],
    min_size_bytes: int = 0,
    follow_junctions: bool = False,
    visited_dirs: Optional[Set] = None,
    exclude_paths: Optional[Set[str]] = None,
) -> List[FileInfo]:
    if not os.path.isdir(root):
        return []

    if visited_dirs is None:
        visited_dirs = set()
    if exclude_paths is None:
        exclude_paths = set()

    root_key = _dir_key(root)
    if root_key in visited_dirs:
        return []
    visited_dirs.add(root_key)

    results: List[FileInfo] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=None):
        pruned = []
        for dirname in dirnames:
            dir_full_path = os.path.normcase(
                os.path.normpath(os.path.join(dirpath, dirname))
            )
            if os.path.normcase(os.path.abspath(dir_full_path)) in exclude_paths:
                continue
            try:
                if not follow_junctions and sys.platform == "win32" and _is_junction(dir_full_path):
                    continue

                key = _dir_key(dir_full_path)
                if key in visited_dirs:
                    continue
                visited_dirs.add(key)

                if is_protected(dir_full_path):
                    continue

            except PermissionError:
                logger.warning("Access denied: %s", dir_full_path)
                continue
            except OSError as exc:
                logger.warning("Cannot access dir %s: %s", dir_full_path, exc)
                continue

            pruned.append(dirname)

        dirnames[:] = pruned

        for fname in filenames:
            file_path = os.path.normcase(
                os.path.normpath(os.path.join(dirpath, fname))
            )
            if os.path.normcase(os.path.abspath(file_path)) in exclude_paths:
                continue
            try:
                if is_protected(file_path):
                    continue
                if is_in_use(file_path):
                    continue
                st = os.stat(file_path)
                size = st.st_size
                if size < min_size_bytes:
                    continue
                mtime = st.st_mtime
            except PermissionError:
                print(f"[WARNING] Access denied: {file_path}", file=sys.stderr)
                continue
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.warning("Cannot stat %s: %s", file_path, exc)
                continue

            results.append(FileInfo(path=file_path, size_bytes=size, mtime=mtime))

    return results


def scan_directories(
    roots: List[str],
    is_protected: Callable[[str], bool],
    is_in_use: Callable[[str], bool],
    min_size_bytes: int = 0,
    follow_junctions: bool = False,
    exclude_paths: Optional[Set[str]] = None,
) -> List[FileInfo]:
    visited_dirs: Set = set()
    seen_paths: Set[str] = set()
    combined: List[FileInfo] = []
    _exclude = exclude_paths or set()

    for root in roots:
        partial = scan_directory(
            root=root,
            is_protected=is_protected,
            is_in_use=is_in_use,
            min_size_bytes=min_size_bytes,
            follow_junctions=follow_junctions,
            visited_dirs=visited_dirs,
            exclude_paths=_exclude,
        )
        for file_info in partial:
            if file_info.path not in seen_paths:
                seen_paths.add(file_info.path)
                combined.append(file_info)

    return combined
