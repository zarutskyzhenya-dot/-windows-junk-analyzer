import os
import sqlite3
import sys
from typing import Optional

if sys.platform == "win32":
    import winreg
else:
    winreg = None  # type: ignore[assignment]

_REGISTRY_LOCATIONS: list[tuple] = []

if sys.platform == "win32" and winreg is not None:
    _REGISTRY_LOCATIONS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]


def _normalize_path(raw: str) -> str:
    return os.path.normcase(os.path.normpath(raw.strip()))


def _read_registry_value(key_handle, value_name: str) -> Optional[str]:
    try:
        data, reg_type = winreg.QueryValueEx(key_handle, value_name)
        if reg_type in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            if isinstance(data, str):
                return data
    except (OSError, FileNotFoundError):
        pass
    return None


def _scan_registry_key(hive: int, subkey: str) -> list[dict[str, str]]:
    if winreg is None:
        return []

    results: list[dict[str, str]] = []
    try:
        root_key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
    except (PermissionError, OSError):
        return results

    try:
        index = 0
        while True:
            try:
                child_name = winreg.EnumKey(root_key, index)
            except OSError:
                break
            index += 1
            try:
                child_key = winreg.OpenKey(root_key, child_name, 0, winreg.KEY_READ)
            except (PermissionError, OSError):
                continue
            try:
                display_name    = _read_registry_value(child_key, "DisplayName") or ""
                install_location = _read_registry_value(child_key, "InstallLocation") or ""
                publisher       = _read_registry_value(child_key, "Publisher") or ""
            finally:
                winreg.CloseKey(child_key)

            if not display_name.strip() or not install_location.strip():
                continue

            install_location = os.path.expandvars(install_location.strip())
            normalized = _normalize_path(install_location)
            if not os.path.exists(normalized):
                continue

            results.append({"display_name": display_name.strip(), "install_location": normalized, "publisher": publisher.strip()})
    finally:
        winreg.CloseKey(root_key)

    return results


def _init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS software_map (
            install_location TEXT PRIMARY KEY,
            display_name     TEXT NOT NULL,
            publisher        TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.commit()


def _is_cache_populated(conn: sqlite3.Connection) -> bool:
    cursor = conn.execute("SELECT COUNT(*) FROM software_map")
    row = cursor.fetchone()
    return row is not None and row[0] > 0


def _load_from_cache(conn: sqlite3.Connection) -> dict[str, str]:
    cursor = conn.execute("SELECT install_location, display_name FROM software_map")
    return {row[0]: row[1] for row in cursor.fetchall()}


def _save_to_cache(conn: sqlite3.Connection, entries: list[dict[str, str]]) -> None:
    conn.executemany(
        "INSERT OR REPLACE INTO software_map (install_location, display_name, publisher) VALUES (:install_location, :display_name, :publisher)",
        entries,
    )
    conn.commit()


def build_software_map(db_path: str) -> dict[str, str]:
    db_dir = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(db_dir, exist_ok=True)

    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(db_path)
        _init_db(conn)

        if _is_cache_populated(conn):
            return _load_from_cache(conn)

        if sys.platform != "win32" or winreg is None:
            return {}

        all_entries: dict[str, dict[str, str]] = {}
        for hive, subkey in _REGISTRY_LOCATIONS:
            for entry in _scan_registry_key(hive, subkey):
                loc = entry["install_location"]
                if loc not in all_entries:
                    all_entries[loc] = entry

        if all_entries:
            _save_to_cache(conn, list(all_entries.values()))

        return {loc: entry["display_name"] for loc, entry in all_entries.items()}

    except sqlite3.Error:
        if sys.platform != "win32" or winreg is None:
            return {}
        fallback: dict[str, str] = {}
        for hive, subkey in _REGISTRY_LOCATIONS:
            for entry in _scan_registry_key(hive, subkey):
                loc = entry["install_location"]
                if loc not in fallback:
                    fallback[loc] = entry["display_name"]
        return fallback
    finally:
        if conn is not None:
            conn.close()


def get_file_owner(path: str, software_map: dict[str, str]) -> Optional[str]:
    if not path or not software_map:
        return None

    normalised_path = _normalize_path(path)
    path_with_sep = normalised_path if normalised_path.endswith(os.sep) else normalised_path + os.sep

    best_match_location: Optional[str] = None
    best_match_length: int = 0

    for location, display_name in software_map.items():
        norm_location = _normalize_path(location)
        norm_location_with_sep = norm_location if norm_location.endswith(os.sep) else norm_location + os.sep

        if path_with_sep.startswith(norm_location_with_sep) or normalised_path == norm_location:
            loc_len = len(norm_location_with_sep)
            if loc_len > best_match_length:
                best_match_length = loc_len
                best_match_location = display_name

    return best_match_location
