#!/usr/bin/env python3
"""
Tail a garbling log and live-report throughput + ETA.

Usage:
    python gates_monitor.py /path/to/logfile

Behavior:
- Follows the file (tail -f style) and parses progress lines:
    1) "[...Z ...] ... garbled: <NUM>[m|b]" (preferred) or legacy "processed:" / "executed:"
    2) "[...Z ...] ... Process gate <INT>"
- Prints latest count, elapsed, overall + window rate, ns/gate, and ETA.

Environment (optional):
    WINDOW_SEC   - sliding window length in seconds (default: 30)
    TARGET_GATES - integer target gates for ETA   (default: 11000000000)
"""
import argparse
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple, List

PROCESSED_RE = re.compile(
    r'^\[(?P<ts>[^\]]+)\].*?(?:garbled|processed|executed):\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s*$'
)
PROCESS_GATE_RE = re.compile(
    r'^\[(?P<ts>[^\]]+)\].*?Process gate\s+(?P<count>\d+)\s*$'
)

@dataclass
class Sample:
    t: float        # epoch seconds (UTC)
    v: int          # gates processed (monotonic, in gates)

def parse_iso_utc(ts: str) -> float:
    # Accept e.g. "2025-08-28T23:49:42Z ..." or "2025-08-28T23:49:42+00:00"
    ts_token = ts.split()[0]
    if ts_token.endswith('Z'):
        ts_token = ts_token[:-1] + '+00:00'
    dt = datetime.fromisoformat(ts_token)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()

def parse_line(line: str) -> Optional[Sample]:
    m = PROCESSED_RE.match(line)
    if m:
        ts = parse_iso_utc(m.group('ts'))
        num = float(m.group('num'))
        unit = m.group('unit').lower() if m.group('unit') else ''
        if unit == 'b':
            v = int(num * 1_000_000_000)
        elif unit == 'm':
            v = int(num * 1_000_000)
        else:
            v = int(num)
        return Sample(ts, v)
    m = PROCESS_GATE_RE.match(line)
    if m:
        ts = parse_iso_utc(m.group('ts'))
        v = int(m.group('count'))
        return Sample(ts, v)
    return None

def fmt_gates(v: int) -> str:
    if v >= 1_000_000_000:
        return f"{v/1_000_000_000:.1f}b"
    if v >= 1_000_000:
        return f"{v/1_000_000:.1f}m"
    return str(v)

def fmt_rate(gps: float) -> str:
    if gps <= 0:
        return "0.00 M/s"
    return f"{gps/1e6:.2f} M/s"

def ns_per_gate(gps: float) -> Optional[float]:
    if gps <= 0:
        return None
    return 1e9 / gps

def fmt_duration(secs: float) -> str:
    if secs < 0:
        secs = 0.0
    m, s = divmod(int(round(secs)), 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s"

def compute_window_rate(samples: List[Sample], window_sec: float) -> float:
    if len(samples) < 2:
        return 0.0
    last = samples[-1]
    cutoff = last.t - window_sec
    first_idx = len(samples) - 1
    while first_idx > 0 and samples[first_idx-1].t >= cutoff:
        first_idx -= 1
    first = samples[first_idx]
    dt = last.t - first.t
    dv = last.v - first.v
    if dt <= 0 or dv <= 0:
        return 0.0
    return dv / dt

def print_status(samples: List[Sample], target_gates: int, window_sec: float) -> None:
    if not samples:
        return
    first = samples[0]
    last = samples[-1]
    elapsed = last.t - first.t
    dv = last.v - first.v
    overall = (dv / elapsed) if elapsed > 0 and dv > 0 else 0.0
    window_rate = compute_window_rate(samples, window_sec)
    nspg = ns_per_gate(overall)
    time_per_1b = (1_000_000_000 / overall) if overall > 0 else float('inf')
    eta = None
    if target_gates > last.v and overall > 0:
        eta = (target_gates - last.v) / overall

    print("="*72)
    print(f"Progress: {fmt_gates(last.v)}  |  Elapsed: {fmt_duration(elapsed)}")
    print(f"Overall:  {fmt_rate(overall)}  (~{nspg:.0f} ns/gate)" if nspg else f"Overall:  {fmt_rate(overall)}")
    print(f"Window({int(window_sec)}s): {fmt_rate(window_rate)}")
    print(f"Avg time per 1B @ overall: {fmt_duration(time_per_1b)}")
    if eta is not None and eta != float('inf'):
        from datetime import datetime, timezone
        finish_ts = datetime.fromtimestamp(samples[-1].t + eta, tz=timezone.utc)
        print(f"ETA to {fmt_gates(target_gates)}: {fmt_duration(eta)}  (finishes ~{finish_ts.isoformat()})")
    sys.stdout.flush()

def tail_file(path: str, target_gates: int, window_sec: float) -> None:
    samples: List[Sample] = []
    last_value: Optional[int] = None

    def open_file():
        return open(path, 'r', encoding='utf-8', errors='ignore')

    # Open and preload existing content using readline() to keep tell() valid
    while True:
        try:
            f = open_file()
            break
        except FileNotFoundError:
            time.sleep(0.5)

    f_stat = os.fstat(f.fileno())
    inode = f_stat.st_ino

    # Preload
    while True:
        line = f.readline()
        if not line:
            break
        s = parse_line(line.strip())
        if s is None:
            continue
        if last_value is not None and s.v <= last_value:
            continue
        samples.append(s)
        last_value = s.v

    pos = f.tell()
    if samples:
        print_status(samples, target_gates, window_sec)

    # Live loop
    while True:
        # Detect rotate/truncate
        try:
            cur_stat = os.stat(path)
        except FileNotFoundError:
            time.sleep(0.5)
            continue

        if cur_stat.st_ino != inode or cur_stat.st_size < pos:
            try:
                f.close()
            except Exception:
                pass
            # Reopen from start and preload again
            while True:
                try:
                    f = open_file()
                    break
                except FileNotFoundError:
                    time.sleep(0.5)
            f_stat = os.fstat(f.fileno())
            inode = f_stat.st_ino
            samples.clear()
            last_value = None
            while True:
                line = f.readline()
                if not line:
                    break
                s = parse_line(line.strip())
                if s is None:
                    continue
                if last_value is not None and s.v <= last_value:
                    continue
                samples.append(s)
                last_value = s.v
            pos = f.tell()
            if samples:
                print_status(samples, target_gates, window_sec)
            time.sleep(0.3)
            continue

        # Read any new lines
        line = f.readline()
        if not line:
            time.sleep(0.3)
            continue
        pos = f.tell()
        s = parse_line(line.strip())
        if s is None:
            continue
        if last_value is not None and s.v <= last_value:
            continue
        samples.append(s)
        last_value = s.v
        # Trim old samples (keep ~max(window*5, 5min))
        cutoff = s.t - max(window_sec * 5, 300)
        while len(samples) > 2 and samples[0].t < cutoff:
            samples.pop(0)

        print_status(samples, target_gates, window_sec)

def main():
    parser = argparse.ArgumentParser(description="Live monitor for garbling logs")
    parser.add_argument("logfile", help="Path to the log file to follow")
    args = parser.parse_args()

    window_sec = float(os.environ.get("WINDOW_SEC", "30"))
    target_gates_env = os.environ.get("TARGET_GATES", "").strip()
    if target_gates_env:
        try:
            target_gates = int(float(target_gates_env))
        except ValueError:
            print(f"Invalid TARGET_GATES '{target_gates_env}', using default 11000000000", file=sys.stderr)
            target_gates = 11_000_000_000
    else:
        target_gates = 11_000_000_000

    try:
        tail_file(args.logfile, target_gates, window_sec)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)

if __name__ == "__main__":
    main()
