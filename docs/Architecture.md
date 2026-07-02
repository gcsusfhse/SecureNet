# System Architecture — SecureNet Guardian

## 1. Design Philosophy

SecureNet Guardian is built as a **modular CLI toolkit**: each security
function lives in its own Python module with a single responsibility. This
keeps the codebase easy to read, test, and extend — an important goal since
the project is meant as a learning resource as much as a working tool.

## 2. High-Level Architecture Diagram

```
                        ┌───────────────────────┐
                        │        main.py         │
                        │   (CLI / argparse)      │
                        └───────────┬─────────────┘
                                    │
        ┌───────────────┬──────────┼──────────┬───────────────┬────────────────┐
        │                │          │          │               │                │
        ▼                ▼          ▼          ▼               ▼                ▼
┌───────────────┐ ┌─────────────┐ ┌────────┐ ┌───────────┐ ┌────────────┐ ┌────────────┐
│host_discovery  │ │  scanner    │ │banner_ │ │password_  │ │integrity_  │ │log_analyzer│
│   .py          │ │   .py       │ │grabber │ │checker.py │ │checker.py  │ │   .py      │
└───────┬────────┘ └──────┬──────┘ └───┬────┘ └─────┬─────┘ └─────┬──────┘ └─────┬──────┘
        │                 │            │            │             │              │
        └─────────────────┴─────┬──────┴────────────┴──────┬──────┴──────────────┘
                                 │                           │
                                 ▼                           ▼
                        ┌────────────────┐         ┌──────────────────┐
                        │    utils.py     │         │ report_generator  │
                        │ (shared helpers)│         │       .py         │
                        └────────────────┘         └─────────┬─────────┘
                                                               │
                                                     ┌─────────┴─────────┐
                                                     ▼                   ▼
                                              HTML Report          PDF Report
```

## 3. Module Responsibilities

| Module | Responsibility |
|---|---|
| `main.py` | Parses CLI arguments and routes them to the correct module. Acts as the single entry point (`python main.py <command>`). |
| `host_discovery.py` | Sweeps a CIDR range using ICMP-style pings to identify live hosts, using a thread pool for speed. |
| `scanner.py` | Performs multithreaded TCP connect scans against common ports and flags well-known risky services. |
| `banner_grabber.py` | Opens a socket to an already-discovered open port and reads any service banner returned. |
| `password_checker.py` | Scores password strength using entropy estimation and rule-based heuristics (length, character variety, common-password matching, sequences). |
| `integrity_checker.py` | Generates SHA-256 baselines for files/directories and verifies them later to detect tampering. |
| `log_analyzer.py` | Parses SSH auth logs and web access logs with regular expressions to detect brute-force patterns and error bursts. |
| `report_generator.py` | Combines results from any of the above modules into a single HTML or PDF report. |
| `utils.py` | Shared helpers: colored console output, timestamps, CSV/JSON export, input validation. |

## 4. Data Flow

1. The user runs a command via `main.py` (e.g. `scan --host 192.168.1.10`).
2. `main.py` calls the relevant module function (e.g. `scanner.scan_ports()`).
3. The module performs its task and returns structured Python data
   (lists of dictionaries) — never printing raw, unstructured strings.
4. `main.py` optionally exports that data via `utils.export_to_csv()` /
   `export_to_json()`, or passes it to `report_generator.py` to build a
   consolidated report.
5. Results are written to `sample_outputs/` (or a user-specified path).

## 5. Concurrency Model

Both `host_discovery.py` and `scanner.py` use
`concurrent.futures.ThreadPoolExecutor` rather than raw threads. This was a
deliberate choice for the project:

- Simpler lifecycle management (no manual thread joining).
- Built-in exception propagation via `future.result()`.
- Easy to tune concurrency with a single `max_workers` parameter.

Network I/O (pings, socket connects) is largely I/O-bound, so Python threads
are appropriate here despite the GIL — CPU-bound work is minimal.

## 6. Extensibility

New assessment modules can be added by:

1. Creating a new file in `src/` with clearly documented functions that
   return structured data (dicts/lists), not printed text.
2. Adding a corresponding subcommand in `main.py`.
3. Optionally feeding the new module's output into `report_generator.py`.
4. Adding unit tests under `tests/`.

## 7. Security & Ethical Boundaries

- All scanning functionality is limited to standard TCP connect scans and
  passive banner reads — no packet crafting, spoofing, or exploitation.
- The toolkit includes reminders (see `utils.is_private_target`) to
  encourage scanning only authorized, typically private, network ranges.
- Passwords analyzed by `password_checker.py` are never written to disk or
  transmitted; they exist only in memory for the duration of the analysis.
