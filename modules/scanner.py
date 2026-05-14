import os
import os.path
import sys
from dataclasses import dataclass
from typing import Callable, List


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


def scan_directory(
    root: str,
    is_protected: Callable[[str], bool],
    is_in_use: Callable[[str], bool],
    min_size_bytes: int = 0,
    follow_junctions: bool = False,
) -> List[FileInfo]:
    if not os.path.isdir(root):
        return []

    results: List[FileInfo] = []

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        for dirname in dirnames[:]:
            dir_full_path = os.path.normcase(
                os.path.normpath(os.path.join(dirpath, dirname))
            )
            try:
                if not follow_junctions and sys.platform == "win32" and _is_junction(dir_full_path):
                    dirnames.remove(dirname)
                    continue
                protected = is_protected(dir_full_path)
            except Exception:
                protected = True

            if protected:
                dirnames.remove(dirname)

        for fname in filenames:
            file_path = os.path.normcase(
                os.path.normpath(os.path.join(dirpath, fname))
            )

            try:
                if is_protected(file_path):
                    continue
                if is_in_use(file_path):
                    continue
                size = os.path.getsize(file_path)
                if size < min_size_bytes:
                    continue
                mtime = os.path.getmtime(file_path)
            except OSError:
                continue
            except Exception:
                continue

            results.append(FileInfo(path=file_path, size_bytes=size, mtime=mtime))

    return results


def scan_directories(
    roots: List[str],
    is_protected: Callable[[str], bool],
    is_in_use: Callable[[str], bool],
    min_size_bytes: int = 0,
    follow_junctions: bool = False,
) -> List[FileInfo]:
    seen_paths: set = set()
    combined: List[FileInfo] = []

    for root in roots:
        partial = scan_directory(
            root=root,
            is_protected=is_protected,
            is_in_use=is_in_use,
            min_size_bytes=min_size_bytes,
            follow_junctions=follow_junctions,
        )
        for file_info in partial:
            if file_info.path not in seen_paths:
                seen_paths.add(file_info.path)
                combined.append(file_info)

    return combined
