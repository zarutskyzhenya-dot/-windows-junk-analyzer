import os
import ctypes
import ctypes.wintypes

# ---------------------------------------------------------------------------
# Protected directory definitions
# ---------------------------------------------------------------------------

_STATIC_PROTECTED_DIRS = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData\Microsoft",
]

_PROTECTED_FILENAMES: frozenset = frozenset({
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
})

_ENV_PROTECTED_DIRS = [
    os.path.join(os.environ.get("APPDATA", ""), "Microsoft"),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft"),
]


def _build_protected_dirs() -> list:
    dirs = []
    for raw in _STATIC_PROTECTED_DIRS + _ENV_PROTECTED_DIRS:
        expanded = os.path.expandvars(raw)
        normalised = os.path.normcase(os.path.normpath(expanded))
        if normalised:
            dirs.append(normalised)
    return dirs


_PROTECTED_DIRS: list = _build_protected_dirs()


def is_protected_path(path: str) -> bool:
    if not isinstance(path, str) or not path:
        return False

    if os.path.basename(path).lower() in _PROTECTED_FILENAMES:
        return True

    try:
        normalised = os.path.normcase(os.path.normpath(path))
    except (ValueError, TypeError):
        return False

    normalised_with_sep = normalised if normalised.endswith(os.sep) else normalised + os.sep

    for protected in _PROTECTED_DIRS:
        protected_with_sep = protected if protected.endswith(os.sep) else protected + os.sep

        if normalised_with_sep.startswith(protected_with_sep):
            return True
        if normalised == protected:
            return True

    try:
        if os.path.islink(path) or _is_junction(path):
            real = os.path.normcase(os.path.normpath(os.path.realpath(path)))
            real_with_sep = real if real.endswith(os.sep) else real + os.sep
            for protected in _PROTECTED_DIRS:
                protected_with_sep = protected if protected.endswith(os.sep) else protected + os.sep
                if real_with_sep.startswith(protected_with_sep) or real == protected:
                    return True
    except (OSError, ValueError):
        pass

    return False


def is_system_file(path: str) -> bool:
    FILE_ATTRIBUTE_SYSTEM: int = 0x4
    INVALID_FILE_ATTRIBUTES: int = 0xFFFFFFFF

    if not isinstance(path, str) or not path:
        return False

    try:
        get_attrs = ctypes.windll.kernel32.GetFileAttributesW
        get_attrs.restype = ctypes.wintypes.DWORD
        get_attrs.argtypes = [ctypes.wintypes.LPCWSTR]

        attrs: int = get_attrs(path)

        if attrs == INVALID_FILE_ATTRIBUTES:
            return False

        return bool(attrs & FILE_ATTRIBUTE_SYSTEM)

    except AttributeError:
        return False
    except OSError:
        return False
    except Exception:
        return False


def _is_junction(path: str) -> bool:
    FILE_ATTRIBUTE_REPARSE_POINT: int = 0x400

    try:
        st = os.lstat(path)
        file_attrs = getattr(st, "st_file_attributes", None)
        if file_attrs is not None:
            return bool(file_attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, ValueError, AttributeError):
        pass

    try:
        get_attrs = ctypes.windll.kernel32.GetFileAttributesW
        get_attrs.restype = ctypes.wintypes.DWORD
        get_attrs.argtypes = [ctypes.wintypes.LPCWSTR]
        attrs: int = get_attrs(path)
        if attrs == 0xFFFFFFFF:
            return False
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:
        return False
