import os
import psutil


def get_open_files() -> set[str]:
    open_files: set[str] = set()

    for proc in psutil.process_iter():
        try:
            file_list = proc.open_files()
        except psutil.AccessDenied:
            continue
        except psutil.NoSuchProcess:
            continue
        except OSError:
            continue

        for f in file_list:
            try:
                normalised = os.path.normcase(os.path.normpath(f.path))
                open_files.add(normalised)
            except (TypeError, ValueError):
                continue

    return open_files


def is_file_in_use(path: str, open_files: set[str]) -> bool:
    if not path:
        return False

    try:
        normalised = os.path.normcase(os.path.normpath(path))
        return normalised in open_files
    except Exception:
        return False
