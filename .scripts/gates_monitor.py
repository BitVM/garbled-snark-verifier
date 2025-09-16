#!/usr/bin/env python3
"""
Tail a cut-and-choose log and live‑report throughput + ETA.

Usage:
    python gates_monitor.py [/path/to/logfile] [--regarbling | --evaluation]

Modes:
- Default (garbling):
    Parses lines like
      "<TS> INFO garble: garbled: <NUM>[m|b] instance=<ID>"
    Tracks per‑instance progress for the first garbling phase.
- --regarbling:
    Parses lines like
      "<TS> INFO regarble: garbled: <NUM>[m|b] instance=<ID>"
    Tracks per‑instance progress for the regarbling phase.
- --evaluation:
    Parses lines like
      "<TS> INFO evaluated: <NUM>[m|b]"
    Tracks single‑stream evaluation throughput and ETA.

Other behavior:
- Follows the file (tail -f style) and shows aggregate stats + ETA.
- Target gates per instance: 11,174,708,821 (fixed for Groth16 verifier).

Environment (optional):
    WINDOW_SEC   - sliding window length in seconds (default: 30)
"""
import argparse
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict

# Patterns configured per mode
RE_GARBLE = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+garble:\s+garbled:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s+instance=(?P<instance>\d+)'
)
RE_REGARBLE = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+regarble:\s+garbled:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s+instance=(?P<instance>\d+)'
)
RE_EVALUATED = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+evaluated:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s*$'
)

# Selected mode (set in main)
MODE = "garbling"  # one of: garbling, regarbling, evaluation

@dataclass
class Sample:
    t: float        # epoch seconds (UTC)
    v: int          # gates processed (monotonic, in gates)
    instance: int   # instance ID

def parse_iso_utc(ts: str) -> float:
    # Accept e.g. "2025-09-16T10:56:02.056992Z"
    if ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()

def parse_line(line: str) -> Optional[Sample]:
    global MODE
    if MODE == "evaluation":
        m = RE_EVALUATED.match(line)
        if not m:
            return None
        ts = parse_iso_utc(m.group('ts'))
        num = float(m.group('num'))
        unit = m.group('unit').lower() if m.group('unit') else ''
        if unit == 'b':
            v = int(num * 1_000_000_000)
        elif unit == 'm':
            v = int(num * 1_000_000)
        else:
            v = int(num)
        # Single stream for evaluation mode; use instance 0
        return Sample(ts, v, 0)
    else:
        regex = RE_GARBLE if MODE == "garbling" else RE_REGARBLE
        m = regex.match(line)
        if m:
            ts = parse_iso_utc(m.group('ts'))
            num = float(m.group('num'))
            unit = m.group('unit').lower() if m.group('unit') else ''
            instance = int(m.group('instance'))
            if unit == 'b':
                v = int(num * 1_000_000_000)
            elif unit == 'm':
                v = int(num * 1_000_000)
            else:
                v = int(num)
            return Sample(ts, v, instance)
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

def compute_window_rate_per_instance(samples: List[Sample], window_sec: float) -> Tuple[float, Dict[int, float]]:
    if len(samples) < 2:
        return 0.0, {}

    # Group samples by instance
    by_instance = defaultdict(list)
    for s in samples:
        by_instance[s.instance].append(s)

    # Calculate per-instance rates
    instance_rates = {}
    total_rate = 0.0

    for inst_id, inst_samples in by_instance.items():
        if len(inst_samples) < 2:
            instance_rates[inst_id] = 0.0
            continue

        last = inst_samples[-1]
        cutoff = last.t - window_sec
        first_idx = len(inst_samples) - 1
        while first_idx > 0 and inst_samples[first_idx-1].t >= cutoff:
            first_idx -= 1
        first = inst_samples[first_idx]

        dt = last.t - first.t
        dv = last.v - first.v
        if dt <= 0 or dv <= 0:
            instance_rates[inst_id] = 0.0
        else:
            rate = dv / dt
            instance_rates[inst_id] = rate
            total_rate += rate

    return total_rate, instance_rates

def print_status(
    samples: List[Sample],
    target_gates: int,
    window_sec: float,
    completed_instances: dict,
    instance_times: dict,
    expected_total: Optional[int] = None,
    max_instance_id: int = -1,
) -> None:
    if not samples:
        return

    # Group samples by instance
    by_instance = defaultdict(list)
    for s in samples:
        by_instance[s.instance].append(s)

    # Calculate aggregate stats
    # Use the real earliest start across all instances (not the trimmed window)
    if instance_times:
        first_time = min(v['start'] for v in instance_times.values() if v and v.get('start') is not None)
    else:
        first_time = min(s.t for s in samples)
    last_time = max(s.t for s in samples)
    elapsed = last_time - first_time

    # Get latest value for each instance and track completed
    latest_per_instance = {}
    active_instances = []
    total_active_gates = 0

    # Detect stalled instances (no updates for >10 seconds with high completion)
    stall_threshold = 10.0  # seconds

    for inst_id, inst_samples in sorted(by_instance.items()):
        if inst_samples:
            latest = inst_samples[-1].v
            latest_time = inst_samples[-1].t
            first_inst_time = inst_samples[0].t
            latest_per_instance[inst_id] = latest

            # Track instance timing
            if inst_id not in instance_times:
                instance_times[inst_id] = {'start': first_inst_time, 'end': None}

            # Check if instance appears to be completed
            time_since_update = last_time - latest_time
            progress_pct = (latest / target_gates) * 100

            # Mark as completed if:
            # 1. Already marked as completed
            # 2. Has reached 11.15b (the typical completion point)
            # 3. Has >99.5% progress and hasn't updated recently
            if inst_id in completed_instances:
                pass  # Already completed
            elif latest >= 11_150_000_000:  # 11.15b gates = typical completion
                completed_instances[inst_id] = latest_time  # Store completion time
                instance_times[inst_id]['end'] = latest_time
            elif progress_pct >= 99.5 and time_since_update > stall_threshold:
                completed_instances[inst_id] = latest_time  # Store completion time
                instance_times[inst_id]['end'] = latest_time
            elif inst_id not in completed_instances:
                active_instances.append(inst_id)
                total_active_gates += latest

    # Calculate rates (only for active instances)
    window_rate, instance_rates = compute_window_rate_per_instance(samples, window_sec)

    # Overall rate based on active instances
    if elapsed > 0 and total_active_gates > 0:
        overall = total_active_gates / elapsed
    else:
        overall = 0.0

    nspg = ns_per_gate(overall)
    time_per_1b = (1_000_000_000 / overall) if overall > 0 else float('inf')

    # Determine total instances first
    if expected_total is not None:
        total_instances = expected_total
    else:
        # Use max instance ID + 1 as total (since instances are 0-indexed)
        all_instance_ids = set(latest_per_instance.keys()) | set(completed_instances.keys())
        if all_instance_ids:
            total_instances = max(max(all_instance_ids), max_instance_id) + 1
        else:
            total_instances = 0

    # ETA based on remaining work for all instances (including not started)
    remaining_gates = 0

    # Add remaining gates for active instances
    for inst_id in active_instances:
        remaining = target_gates - latest_per_instance.get(inst_id, 0)
        if remaining > 0:
            remaining_gates += remaining

    # Add full gates for instances that haven't started yet
    if total_instances > 0:
        started_instances = len(latest_per_instance) + len(completed_instances) - len(set(latest_per_instance.keys()) & set(completed_instances.keys()))
        not_started = max(0, total_instances - started_instances)
        remaining_gates += not_started * target_gates

    eta = None
    if remaining_gates > 0 and window_rate > 0:
        eta = remaining_gates / window_rate

    # Clear screen for clean update
    phase = {
        "garbling": "GARBLING",
        "regarbling": "REGARBLING",
        "evaluation": "EVALUATION",
    }[MODE]

    print("\033[2J\033[H")  # Clear screen and move to top
    print("="*80)
    if MODE == "evaluation":
        print(f"{phase} PHASE MONITOR")
    else:
        print(f"{phase} PHASE MONITOR - {len(active_instances)} active, {len(completed_instances)} completed, {total_instances} total")
    print("="*80)

    # Per-instance progress
    if MODE == "evaluation":
        print("\nPROGRESS:")
        print("-" * 75)
    else:
        print("\nPER-INSTANCE PROGRESS:")
        print("-" * 75)

    # Show active instances first
    for inst_id in sorted(latest_per_instance.keys()):
        gates = latest_per_instance[inst_id]
        rate = instance_rates.get(inst_id, 0.0)

        progress_pct = (gates / target_gates) * 100

        if inst_id in completed_instances:
            # Calculate instance duration
            if inst_id in instance_times and instance_times[inst_id]['end']:
                duration = instance_times[inst_id]['end'] - instance_times[inst_id]['start']
                time_str = fmt_duration(duration)
            else:
                time_str = "N/A"
            if MODE == "evaluation":
                print(f"  {fmt_gates(gates):>10s}  |   COMPLETED  |  Time: {time_str:>10s}")
            else:
                print(f"  Instance {inst_id:2d}: {fmt_gates(gates):>10s}  |   COMPLETED  |  Time: {time_str:>10s}")
        else:
            # Show current runtime for active instances
            if inst_id in instance_times:
                runtime = last_time - instance_times[inst_id]['start']
                runtime_str = fmt_duration(runtime)
            else:
                runtime_str = "N/A"

            # Check if likely completed (>99% and stalled)
            time_since_update = last_time - by_instance[inst_id][-1].t
            if progress_pct >= 99.0 and time_since_update > 10.0:
                if MODE == "evaluation":
                    print(f"  {fmt_gates(gates):>10s}  |   FINISHING  |  Time: {runtime_str:>10s}")
                else:
                    print(f"  Instance {inst_id:2d}: {fmt_gates(gates):>10s}  |   FINISHING  |  Time: {runtime_str:>10s}")
            else:
                status = f"{progress_pct:5.1f}%"
                if MODE == "evaluation":
                    print(f"  {fmt_gates(gates):>10s}  |  {status:>10s}  |  {fmt_rate(rate):>10s} ({runtime_str})")
                else:
                    print(f"  Instance {inst_id:2d}: {fmt_gates(gates):>10s}  |  {status:>10s}  |  {fmt_rate(rate):>10s} ({runtime_str})")

    # Aggregate stats
    print("\n" + "="*70)
    print(f"ACTIVE GATES: {fmt_gates(total_active_gates):>10s}  |  Elapsed: {fmt_duration(elapsed)}")
    print(f"Overall Rate: {fmt_rate(overall):>10s}  (~{nspg:.0f} ns/gate)" if nspg else f"Overall Rate: {fmt_rate(overall):>10s}")
    print(f"Window Rate({int(window_sec)}s): {fmt_rate(window_rate):>10s}")

    if len(active_instances) > 0:
        avg_progress = total_active_gates / len(active_instances) if active_instances else 0
        avg_pct = (avg_progress / target_gates) * 100
        print(f"Avg progress: {fmt_gates(int(avg_progress)):>10s}  ({avg_pct:.1f}%)")

    # Calculate expected total time for all instances and progress
    if MODE != "evaluation" and total_instances > 0:
        total_gates_all = total_instances * target_gates

        # Calculate how much work is done
        completed_gates = len(completed_instances) * target_gates + total_active_gates
        progress_pct = (completed_gates / total_gates_all) * 100 if total_gates_all > 0 else 0

        print(f"\n{'='*70}")
        print(f"PROGRESS: {progress_pct:.1f}% complete ({len(completed_instances)}/{total_instances} instances done)")

        # Calculate expected total time based on actual progress and elapsed time
        if progress_pct > 0 and elapsed > 0:
            # Project total time based on current progress
            expected_total_time = elapsed / (progress_pct / 100)
            print(f"Expected Total Time: {fmt_duration(expected_total_time)} (for all {total_instances} instances)")
            print(f"Time Elapsed (actual): {fmt_duration(elapsed)}")

            # Time remaining based on projection
            time_remaining = expected_total_time - elapsed
            if time_remaining > 0:
                print(f"Time Remaining: {fmt_duration(time_remaining)}")

                from datetime import datetime, timezone
                finish_ts = datetime.fromtimestamp(last_time + time_remaining, tz=timezone.utc)
                print(f"Est. completion: {finish_ts.isoformat()}")
        elif window_rate > 0 and eta is not None and eta > 0:
            # Fall back to window rate calculation if no progress yet
            print(f"Time Remaining (est): {fmt_duration(eta)}")
            from datetime import datetime, timezone
            finish_ts = datetime.fromtimestamp(last_time + eta, tz=timezone.utc)
            print(f"Est. completion: {finish_ts.isoformat()}")
    elif len(active_instances) == 0 and len(completed_instances) > 0:
        print(f"\nAll instances completed!")

        # Calculate total time and average
        total_duration = 0
        valid_durations = 0
        for inst_id in sorted(completed_instances.keys()):
            if inst_id in instance_times and instance_times[inst_id]['end'] and instance_times[inst_id]['start']:
                duration = instance_times[inst_id]['end'] - instance_times[inst_id]['start']
                total_duration += duration
                valid_durations += 1

        if valid_durations > 0:
            avg_duration = total_duration / valid_durations
            print(f"\n{'='*70}")
            print(f"FINAL SUMMARY:")
            print(f"Total instances completed: {len(completed_instances)}")
            print(f"Average time per instance: {fmt_duration(avg_duration)}")
            print(f"Total processing time: {fmt_duration(elapsed)}")

    sys.stdout.flush()

def tail_file(path: str, target_gates: int, window_sec: float) -> None:
    samples: List[Sample] = []
    last_value_per_instance: Dict[int, int] = {}
    completed_instances: Dict[int, float] = {}  # instance_id -> completion_time
    instance_times: Dict[int, dict] = {}  # instance_id -> {'start': time, 'end': time}
    max_instance_id = -1  # Track highest instance ID seen
    expected_total: Optional[int] = None

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
        if MODE != "evaluation" and "Garbler: Creating" in line:
            m2 = re.search(r'Creating\s+(\d+)\s+instances\s*\((\d+)\s+to finalize\)', line)
            if m2:
                total = int(m2.group(1))
                to_finalize = int(m2.group(2))
                expected_total = (total - to_finalize) if MODE == "regarbling" else total
                print(
                    f"Detected instances from 'Creating': total={total}, to_finalize={to_finalize}, expected_total={expected_total}",
                    file=sys.stderr,
                )
        if MODE != "evaluation" and expected_total is None and "Starting cut-and-choose with" in line:
            m = re.search(r'with (\d+) instances', line)
            if m:
                expected_total = int(m.group(1))
                print(f"Detected {expected_total} total instances from log", file=sys.stderr)
        s = parse_line(line.strip())
        if s is None:
            continue

        # Track first appearance time
        if s.instance not in instance_times:
            instance_times[s.instance] = {'start': s.t, 'end': None}

        # Track max instance ID
        max_instance_id = max(max_instance_id, s.instance)

        # Check if this is progress for this instance (not going backwards)
        last_val = last_value_per_instance.get(s.instance)
        if last_val is not None and s.v <= last_val:
            continue
        samples.append(s)
        last_value_per_instance[s.instance] = s.v

        # Mark as completed if reached target
        if s.v >= target_gates:
            completed_instances[s.instance] = s.t
            instance_times[s.instance]['end'] = s.t

    pos = f.tell()
    if samples:
        print_status(samples, target_gates, window_sec, completed_instances, instance_times, expected_total, max_instance_id)

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
            last_value_per_instance.clear()
            completed_instances.clear()
            instance_times.clear()
            expected_total = None
            max_instance_id = -1
            while True:
                line = f.readline()
                if not line:
                    break
                if MODE != "evaluation" and "Garbler: Creating" in line:
                    m2 = re.search(r'Creating\s+(\d+)\s+instances\s*\((\d+)\s+to finalize\)', line)
                    if m2:
                        total = int(m2.group(1))
                        to_finalize = int(m2.group(2))
                        expected_total = (total - to_finalize) if MODE == "regarbling" else total
                        print(
                            f"Detected instances from 'Creating': total={total}, to_finalize={to_finalize}, expected_total={expected_total}",
                            file=sys.stderr,
                        )
                if MODE != "evaluation" and expected_total is None and "Starting cut-and-choose with" in line:
                    m = re.search(r'with (\d+) instances', line)
                    if m:
                        expected_total = int(m.group(1))
                        print(f"Detected {expected_total} total instances from log", file=sys.stderr)
                s = parse_line(line.strip())
                if s is None:
                    continue
                last_val = last_value_per_instance.get(s.instance)
                if last_val is not None and s.v <= last_val:
                    continue
                samples.append(s)
                last_value_per_instance[s.instance] = s.v
                # Track instance timing
                if s.instance not in instance_times:
                    instance_times[s.instance] = {'start': s.t, 'end': None}
                # Track max instance ID
                max_instance_id = max(max_instance_id, s.instance)
                # Mark as completed if reached target
                if s.v >= target_gates:
                    completed_instances[s.instance] = s.t
                    instance_times[s.instance]['end'] = s.t
            pos = f.tell()
            if samples:
                print_status(samples, target_gates, window_sec, completed_instances, instance_times, expected_total, max_instance_id)
            time.sleep(0.3)
            continue

        # Read any new lines
        line = f.readline()
        if not line:
            time.sleep(0.3)
            continue
        pos = f.tell()
        if MODE != "evaluation" and "Garbler: Creating" in line:
            m2 = re.search(r'Creating\s+(\d+)\s+instances\s*\((\d+)\s+to finalize\)', line)
            if m2:
                total = int(m2.group(1))
                to_finalize = int(m2.group(2))
                expected_total = (total - to_finalize) if MODE == "regarbling" else total
                print(
                    f"Detected instances from 'Creating': total={total}, to_finalize={to_finalize}, expected_total={expected_total}",
                    file=sys.stderr,
                )
        if MODE != "evaluation" and expected_total is None and "Starting cut-and-choose with" in line:
            m = re.search(r'with (\d+) instances', line)
            if m:
                expected_total = int(m.group(1))
                print(f"Detected {expected_total} total instances from log", file=sys.stderr)
        s = parse_line(line.strip())
        if s is None:
            continue

        # Track instance timing
        if s.instance not in instance_times:
            instance_times[s.instance] = {'start': s.t, 'end': None}

        # Track max instance ID
        max_instance_id = max(max_instance_id, s.instance)

        # Handle instance restarts (when instance ID reappears with lower value)
        last_val = last_value_per_instance.get(s.instance)
        if last_val is not None and s.v < last_val:
            # Instance restarted - remove from completed set if it was there
            if s.instance in completed_instances:
                del completed_instances[s.instance]
            # Reset its timing
            instance_times[s.instance] = {'start': s.t, 'end': None}
            # Reset its last value
            last_value_per_instance[s.instance] = s.v
        else:
            last_value_per_instance[s.instance] = s.v

        samples.append(s)

        # Mark as completed if reached target
        if s.v >= target_gates:
            completed_instances[s.instance] = s.t
            instance_times[s.instance]['end'] = s.t

        # Trim old samples but keep recent data for all active instances
        if samples:
            # Keep samples for active (non-completed) instances within window
            active_samples = []
            cutoff = max(s.t for s in samples[-100:]) - max(window_sec * 5, 300)

            for s in samples:
                # Keep if recent OR if it's for an active instance
                if s.t >= cutoff or s.instance not in completed_instances:
                    active_samples.append(s)
            samples = active_samples

        print_status(samples, target_gates, window_sec, completed_instances, instance_times, expected_total, max_instance_id)

def main():
    global MODE
    parser = argparse.ArgumentParser(description="Live monitor for garbling/regarbling/evaluation logs")
    parser.add_argument("logfile", nargs="?", default="2from3.log", help="Path to the log file to follow (default: 2from3.log)")
    parser.add_argument("--regarbling", action="store_true", help="Track regarbling flow (match 'regarble: garbled: ...')")
    parser.add_argument("--evaluation", action="store_true", help="Track evaluation throughput (match 'evaluated: ...')")
    args = parser.parse_args()

    # Determine mode (mutually exclusive flags)
    if args.regarbling and args.evaluation:
        print("Use only one of --regarbling or --evaluation", file=sys.stderr)
        sys.exit(2)
    MODE = "evaluation" if args.evaluation else ("regarbling" if args.regarbling else "garbling")

    window_sec = float(os.environ.get("WINDOW_SEC", "30"))
    # Fixed target: each Groth16 instance requires exactly this many gates
    target_gates = 11_174_708_821

    try:
        tail_file(args.logfile, target_gates, window_sec)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)

if __name__ == "__main__":
    main()
