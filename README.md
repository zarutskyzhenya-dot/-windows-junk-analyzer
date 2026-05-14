# Windows Junk Analyzer

Scans Windows directories for junk files and generates a detailed report with color terminal output.

## Features

- Scans one or more directories recursively
- Skips protected system paths (`C:\Windows`, `C:\Program Files`, etc.)
- Skips files currently in use by running processes
- Skips junction points to avoid cross-drive duplicates
- Detects junk by category: temp files, old files, large files, logs, cache
- Shows software ownership via Windows registry
- Color terminal output with Unicode box drawing
- Saves plain-text report to file

## Requirements

```
psutil
```

Install:
```
pip install psutil
```

## Usage

**Interactive mode** (asks for directories on start):
```
run.bat
```

**Command line:**
```
python main.py --scan "C:\Users\%USERNAME%\AppData\Local\Temp"
python main.py --scan "C:\" --min-size 10 --output report.txt
python main.py --scan "C:\" "D:\" --no-software-map
```

## Options

| Flag | Description |
|------|-------------|
| `--scan PATH [PATH ...]` | Directories to scan (interactive if omitted) |
| `--output FILE` | Save report to file (default: print to terminal) |
| `--min-size MB` | Skip files smaller than MB megabytes (default: 0) |
| `--no-software-map` | Skip registry scan for faster results |
| `--follow-junctions` | Follow junction points (skipped by default) |
| `--db PATH` | Custom SQLite cache path for software map |

## Junk categories

| Category | Description |
|----------|-------------|
| `temp_extension` | Files with extensions: `.tmp`, `.dmp`, `.bak`, `.old`, `.swp`, etc. |
| `old_file` | Not modified in more than 180 days |
| `large_file` | Larger than 500 MB |
| `empty_file` | Zero bytes |
| `log_file` | Extensions: `.log`, `.etl` |
| `cache_file` | Extensions: `.cache`, `.db`, `.thumbs` |

## Project structure

```
junk_analyzer/
├── main.py               — entry point, CLI, pipeline wiring
├── run.bat               — double-click launcher for Windows
└── modules/
    ├── protection.py     — protected path detection (system dirs, junctions)
    ├── software_map.py   — registry scan, SQLite cache, file ownership
    ├── process_check.py  — open file detection via psutil
    ├── scanner.py        — directory walker, returns FileInfo list
    ├── rules.py          — junk classification rules
    └── report.py         — report builder (plain text + color terminal)
```

## Example output

```
╔══════════════════════════════════╗
║  Windows Junk Analyzer — Report  ║
╚══════════════════════════════════╝
  Generated: 2026-05-14 10:36:28

  Total junk files : 85
  Total size       : 7.81 GB

  By category
┌────────────────┬────────┬────────────┐
│ Category       │  Files │       Size │
├────────────────┼────────┼────────────┤
│ old_file       │     61 │    5.90 GB │
│ temp_extension │     19 │    1.77 GB │
│ log_file       │      8 │   118.5 MB │
└────────────────┴────────┴────────────┘
```
