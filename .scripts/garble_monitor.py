#!/usr/bin/env python3
"""
Monitor for simple groth16_garble example logs with proper scopes.

Usage:
    python garble_monitor.py [/path/to/logfile]

Parses lines like:
    "<TS> INFO garble: garbled: <NUM>[m|b]"        (first garbling)
    "<TS> INFO regarble: garbled: <NUM>[m|b]"      (regarbling)
    "<TS> INFO evaluate: evaluated: <NUM>[m|b]"     (evaluation)

Shows live throughput, progress, and ETA for each phase.
"""
import argparse
import os
import re
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List, Tuple

# Patterns for different phases with scopes
RE_GARBLE = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+garble:\s+garbled:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?'
)
RE_REGARBLE = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+regarble:\s+garbled:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?'
)
RE_EVALUATE = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+evaluate:\s+evaluated:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?'
)

# Phase completion patterns
RE_GARBLE_DONE = re.compile(r'garbling:\s+in\s+(?P<time>[\d\.]+)s')
RE_REGARBLE_DONE = re.compile(r'regarbling:\s+in\s+(?P<time>[\d\.]+)s')
RE_EVALUATE_DONE = re.compile(r'evaluation:\s+in\s+(?P<time>[\d\.]+)s')

@dataclass
class Sample:
    t: float  # epoch seconds (UTC)
    v: int    # gates processed (monotonic, in gates)
    phase: str  # 'garble', 'regarble', or 'evaluate'

def parse_iso_utc(ts: str) -> float:
    if ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()

def parse_line(line: str) -> Optional[Sample]:
    # Check first garbling
    m = RE_GARBLE.match(line)
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
        return Sample(ts, v, 'garble')

    # Check regarbling
    m = RE_REGARBLE.match(line)
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
        return Sample(ts, v, 'regarble')

    # Check evaluation
    m = RE_EVALUATE.match(line)
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
        return Sample(ts, v, 'evaluate')

    return None

def check_phase_completion(line: str) -> Optional[Tuple[str, float]]:
    """Check if line indicates phase completion."""
    m = RE_GARBLE_DONE.search(line)
    if m:
        return ('garble', float(m.group('time')))

    m = RE_REGARBLE_DONE.search(line)
    if m:
        return ('regarble', float(m.group('time')))

    m = RE_EVALUATE_DONE.search(line)
    if m:
        return ('evaluate', float(m.group('time')))

    return None

def fmt_gates(v: int) -> str:
    if v >= 1_000_000_000:
        return f"{v/1_000_000_000:.2f}b"
    if v >= 1_000_000:
        return f"{v/1_000_000:.1f}m"
    return str(v)

def fmt_rate(gps: float) -> str:
    if gps <= 0:
        return "0.00 M/s"
    return f"{gps/1e6:.2f} M/s"

def fmt_duration(secs: float) -> str:
    if secs < 0:
        secs = 0.0
    m, s = divmod(int(round(secs)), 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s"

def compute_window_rate(samples: List[Sample], window_sec: float) -> float:
    """Compute rate over sliding window."""
    if len(samples) < 2:
        return 0.0

    last = samples[-1]
    cutoff = last.t - window_sec

    # Find first sample in window
    first_idx = len(samples) - 1
    while first_idx > 0 and samples[first_idx-1].t >= cutoff:
        first_idx -= 1

    first = samples[first_idx]
    dt = last.t - first.t
    dv = last.v - first.v

    if dt <= 0 or dv <= 0:
        return 0.0

    return dv / dt

def print_status(
    phase_samples: dict,
    phase_completed: dict,
    target_gates: int,
    window_sec: float
) -> None:
    print("\033[2J\033[H")  # Clear screen
    print("=" * 80)
    print("GROTH16 GARBLE/EVALUATE MONITOR")
    print("=" * 80)

    # Show each phase
    phases = ['garble', 'regarble', 'evaluate']
    for phase in phases:
        samples = phase_samples.get(phase, [])
        completion_time = phase_completed.get(phase)

        phase_name = {
            'garble': 'GARBLING',
            'regarble': 'REGARBLING',
            'evaluate': 'EVALUATION'
        }[phase]

        if not samples and completion_time is None:
            # Phase hasn't started yet
            continue

        print(f"\n{phase_name:12s}:")
        print("-" * 75)

        if completion_time is not None:
            # Phase completed
            print(f"  Status:     COMPLETED in {fmt_duration(completion_time)}")
            if samples:
                total_gates = samples[-1].v
                avg_rate = total_gates / completion_time if completion_time > 0 else 0
                print(f"  Total:      {fmt_gates(total_gates)}")
                print(f"  Avg Rate:   {fmt_rate(avg_rate)}")
        else:
            # Phase in progress
            if not samples:
                continue

            latest_gates = samples[-1].v
            first_time = samples[0].t
            last_time = samples[-1].t
            elapsed = last_time - first_time

            # Calculate rates
            window_rate = compute_window_rate(samples, window_sec)
            overall_rate = latest_gates / elapsed if elapsed > 0 else 0

            # Progress
            progress_pct = (latest_gates / target_gates) * 100 if target_gates > 0 else 0

            print(f"  Progress:   {fmt_gates(latest_gates):>10s} ({progress_pct:5.1f}%)")
            print(f"  Elapsed:    {fmt_duration(elapsed)}")
            print(f"  Overall:    {fmt_rate(overall_rate)}")
            print(f"  Window({int(window_sec)}s): {fmt_rate(window_rate)}")

            # ETA
            if window_rate > 0 and target_gates > latest_gates:
                remaining = target_gates - latest_gates
                eta = remaining / window_rate
                print(f"  ETA:        {fmt_duration(eta)}")

    # Show concurrent status if both regarble and evaluate are active
    regarble_active = 'regarble' in phase_samples and 'regarble' not in phase_completed
    evaluate_active = 'evaluate' in phase_samples and 'evaluate' not in phase_completed

    if regarble_active and evaluate_active:
        print("\n" + "=" * 80)
        print("CONCURRENT EXECUTION:")

        # Compare rates
        regarble_rate = compute_window_rate(phase_samples.get('regarble', []), window_sec)
        evaluate_rate = compute_window_rate(phase_samples.get('evaluate', []), window_sec)

        if regarble_rate > 0 and evaluate_rate > 0:
            ratio = evaluate_rate / regarble_rate
            print(f"  Evaluate/Regarble ratio: {ratio:.2f}x")
            if ratio < 0.95:
                print(f"  ⚠️  Evaluation is slower - may be bottlenecked")
            elif ratio > 1.05:
                print(f"  ✓  Regarbling is the bottleneck (expected)")

    print("\n" + "=" * 80)
    sys.stdout.flush()

def tail_file(path: str, target_gates: int, window_sec: float) -> None:
    phase_samples = {}  # phase -> List[Sample]
    phase_completed = {}  # phase -> completion_time_seconds

    def open_file():
        return open(path, 'r', encoding='utf-8', errors='ignore')

    # Wait for file to exist
    while True:
        try:
            f = open_file()
            break
        except FileNotFoundError:
            time.sleep(0.5)

    f_stat = os.fstat(f.fileno())
    inode = f_stat.st_ino

    # Preload existing content
    while True:
        line = f.readline()
        if not line:
            break

        # Check for completion
        completion = check_phase_completion(line)
        if completion:
            phase, duration = completion
            phase_completed[phase] = duration
            continue

        # Parse progress
        s = parse_line(line.strip())
        if s:
            if s.phase not in phase_samples:
                phase_samples[s.phase] = []
            # Only add if it's new progress
            if not phase_samples[s.phase] or s.v > phase_samples[s.phase][-1].v:
                phase_samples[s.phase].append(s)

    pos = f.tell()
    print_status(phase_samples, phase_completed, target_gates, window_sec)

    # Live monitoring loop
    while True:
        # Check for file rotation
        try:
            cur_stat = os.stat(path)
        except FileNotFoundError:
            time.sleep(0.5)
            continue

        if cur_stat.st_ino != inode or cur_stat.st_size < pos:
            # File rotated, reopen
            try:
                f.close()
            except Exception:
                pass
            while True:
                try:
                    f = open_file()
                    break
                except FileNotFoundError:
                    time.sleep(0.5)
            f_stat = os.fstat(f.fileno())
            inode = f_stat.st_ino
            phase_samples.clear()
            phase_completed.clear()

            # Re-read from start
            while True:
                line = f.readline()
                if not line:
                    break

                completion = check_phase_completion(line)
                if completion:
                    phase, duration = completion
                    phase_completed[phase] = duration
                    continue

                s = parse_line(line.strip())
                if s:
                    if s.phase not in phase_samples:
                        phase_samples[s.phase] = []
                    if not phase_samples[s.phase] or s.v > phase_samples[s.phase][-1].v:
                        phase_samples[s.phase].append(s)

            pos = f.tell()
            print_status(phase_samples, phase_completed, target_gates, window_sec)
            time.sleep(0.3)
            continue

        # Read new lines
        line = f.readline()
        if not line:
            time.sleep(0.3)
            continue

        pos = f.tell()

        # Check for completion
        completion = check_phase_completion(line)
        if completion:
            phase, duration = completion
            phase_completed[phase] = duration

        # Parse progress
        s = parse_line(line.strip())
        if s:
            if s.phase not in phase_samples:
                phase_samples[s.phase] = []
            # Only add if it's new progress
            if not phase_samples[s.phase] or s.v > phase_samples[s.phase][-1].v:
                phase_samples[s.phase].append(s)

                # Trim old samples
                for phase, samples in phase_samples.items():
                    if phase not in phase_completed and len(samples) > 1000:
                        # Keep last 1000 samples for active phases
                        phase_samples[phase] = samples[-1000:]

        print_status(phase_samples, phase_completed, target_gates, window_sec)

def main():
    parser = argparse.ArgumentParser(description="Monitor groth16_garble example logs")
    parser.add_argument(
        "logfile",
        nargs="?",
        default="garble.log",
        help="Path to log file (default: garble.log)"
    )
    parser.add_argument(
        "--window",
        type=int,
        default=30,
        help="Sliding window in seconds for rate calculation (default: 30)"
    )
    parser.add_argument(
        "--target",
        type=float,
        default=11.175,
        help="Target gates in billions (default: 11.175)"
    )
    args = parser.parse_args()

    target_gates = int(args.target * 1_000_000_000)

    try:
        tail_file(args.logfile, target_gates, args.window)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)

if __name__ == "__main__":
    main()