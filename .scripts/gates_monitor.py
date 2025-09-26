#!/usr/bin/env python3
"""
Tail a cut-and-choose log and live-report throughput + ETA.

Usage:
    python gates_monitor.py [/path/to/logfile]
                               [--garbling | --regarbling | --evaluation]

Modes:
- Default (auto):
    Detects the active phase on the fly (garbling → regarbling → evaluation)
    and switches views automatically while tailing the live log.
- --garbling:
    Parses lines like
      "<TS> INFO garble: garbled: <NUM>[m|b] instance=<ID>"
    Tracks per-instance progress for the first garbling phase only.
- --regarbling:
    Parses lines like
      "<TS> INFO regarble: garbled: <NUM>[m|b] instance=<ID>"
      "<TS> INFO regarble2send: garbled: <NUM>[m|b] instance=<ID>"
      and the legacy spans
      "<TS> INFO garble2evaluation: garbled: <NUM>[m|b] instance=<ID>"
      (and the common alias "garble2evaluator").
    Tracks per-instance progress for the entire regarbling stage, including
    the evaluation-garbling streams for finalized instances.
- --evaluation:
    Parses lines like
      "<TS> INFO evaluated: <NUM>[m|b]"
    Tracks single-stream evaluation throughput and ETA.

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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# Patterns configured per mode
RE_GARBLE = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+garble:\s+garbled:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s+instance=(?P<instance>\d+)'
)
RE_REGARBLE = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+regarble:\s+garbled:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s+instance=(?P<instance>\d+)'
)
# New span name used for regarble-to-send streaming garbling
RE_REGARBLE2SEND = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+regarble2send:\s+garbled:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s+instance=(?P<instance>\d+)'
)
# During regarbling, finalized instances are garbled again for evaluation
# under a separate span name. Support both the canonical name and a common
# alias spelling.
RE_G2EVAL = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+garble2evaluation:\s+garbled:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s+instance=(?P<instance>\d+)'
)
RE_G2EVALUATOR = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+garble2evaluator:\s+garbled:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s+instance=(?P<instance>\d+)'
)
RE_EVALUATED = re.compile(
    r'^(?P<ts>[\d\-T:\.Z]+)\s+INFO\s+evaluate:\s+evaluated:\s*(?P<num>[\d\.]+)\s*(?P<unit>[mbMB])?\s*(?:instance=(?P<instance>\d+))?\s*$'
)

# Selected mode (set in main). "auto" selects phases dynamically.
MODE = "garbling"  # one of: auto, garbling, regarbling, evaluation

# Phase ordering used for auto mode tie-breaking
PHASES = ("garbling", "regarbling", "evaluation")
PHASE_ORDER_INDEX = {phase: idx for idx, phase in enumerate(PHASES)}
PHASE_LABELS = {
    "garbling": "GARBLING",
    "regarbling": "REGARBLING",
    "evaluation": "EVALUATION",
}

@dataclass
class Sample:
    t: float        # epoch seconds (UTC)
    v: int          # gates processed (monotonic, in gates)
    instance: int   # instance ID
    phase: str      # phase label ('garbling', 'regarbling', 'evaluation')


@dataclass
class PhaseState:
    samples: List[Sample] = field(default_factory=list)
    last_value_per_instance: Dict[int, int] = field(default_factory=dict)
    completed_instances: Dict[int, float] = field(default_factory=dict)
    instance_times: Dict[int, dict] = field(default_factory=dict)
    max_instance_id: int = -1
    expected_total: Optional[int] = None
    evaluation_instance_counter: int = 0  # For assigning instance IDs when not provided
    evaluation_last_ts: Dict[float, int] = field(default_factory=dict)  # Map timestamp to instance

def parse_iso_utc(ts: str) -> float:
    # Accept e.g. "2025-09-16T10:56:02.056992Z"
    if ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()

def to_gates(num_str: str, unit: Optional[str]) -> int:
    unit_norm = (unit or '').lower()
    num = float(num_str)
    if unit_norm == 'b':
        return int(num * 1_000_000_000)
    if unit_norm == 'm':
        return int(num * 1_000_000)
    return int(num)

def parse_line_auto(line: str) -> Optional[Sample]:
    m = RE_GARBLE.match(line)
    if m:
        ts = parse_iso_utc(m.group('ts'))
        v = to_gates(m.group('num'), m.group('unit'))
        instance = int(m.group('instance'))
        return Sample(ts, v, instance, 'garbling')

    for pattern in (RE_REGARBLE, RE_REGARBLE2SEND, RE_G2EVAL, RE_G2EVALUATOR):
        m = pattern.match(line)
        if m:
            ts = parse_iso_utc(m.group('ts'))
            v = to_gates(m.group('num'), m.group('unit'))
            instance = int(m.group('instance'))
            return Sample(ts, v, instance, 'regarbling')

    m = RE_EVALUATED.match(line)
    if m:
        ts = parse_iso_utc(m.group('ts'))
        v = to_gates(m.group('num'), m.group('unit'))
        instance = int(m.group('instance')) if m.group('instance') else None
        return Sample(ts, v, instance, 'evaluation')

    return None

def parse_line(line: str) -> Optional[Sample]:
    global MODE
    if MODE == "auto":
        return parse_line_auto(line)

    if MODE == "evaluation":
        m = RE_EVALUATED.match(line)
        if not m:
            return None
        ts = parse_iso_utc(m.group('ts'))
        v = to_gates(m.group('num'), m.group('unit'))
        instance = int(m.group('instance')) if m.group('instance') else None
        return Sample(ts, v, instance, 'evaluation')
    else:
        if MODE == "garbling":
            m = RE_GARBLE.match(line)
        else:  # regarbling stage may include multiple spans
            m = (
                RE_REGARBLE.match(line)
                or RE_REGARBLE2SEND.match(line)
                or RE_G2EVAL.match(line)
                or RE_G2EVALUATOR.match(line)
            )

        if m:
            ts = parse_iso_utc(m.group('ts'))
            instance = int(m.group('instance'))
            v = to_gates(m.group('num'), m.group('unit'))
            phase = 'garbling' if MODE == 'garbling' else 'regarbling'
            return Sample(ts, v, instance, phase)
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

def process_sample(state: PhaseState, sample: Sample, target_gates: int, *, ignore_non_increasing: bool) -> bool:
    """Update per-phase state with a new sample.

    Returns True if the sample was appended (i.e. new progress recorded).
    """
    # Handle evaluation mode with no instance IDs
    if sample.phase == 'evaluation' and sample.instance is None:
        # Assign instance based on value pattern - find which instance this belongs to
        found_instance = None
        for inst_id, last_v in state.last_value_per_instance.items():
            # If this value is a reasonable progression from the last value
            if sample.v >= last_v and sample.v - last_v < 100_000_000:  # Less than 100M gate jump
                found_instance = inst_id
                break

        if found_instance is None:
            # This is a new instance or a reset
            if sample.v < 10_000_000:  # Small value, likely a new instance starting
                sample.instance = state.evaluation_instance_counter
                state.evaluation_instance_counter += 1
            else:
                # Try to find the best match based on expected progress
                sample.instance = 0  # Default to instance 0
        else:
            sample.instance = found_instance

    last_val = state.last_value_per_instance.get(sample.instance)

    if ignore_non_increasing and last_val is not None and sample.v <= last_val:
        return False

    if sample.instance not in state.instance_times:
        state.instance_times[sample.instance] = {'start': sample.t, 'end': None}

    # Keep track of highest instance index seen for total estimation
    state.max_instance_id = max(state.max_instance_id, sample.instance)

    # Handle instance restarts (value decreased) when not ignoring duplicates
    if not ignore_non_increasing and last_val is not None and sample.v < last_val:
        if sample.instance in state.completed_instances:
            del state.completed_instances[sample.instance]
        state.instance_times[sample.instance] = {'start': sample.t, 'end': None}

    state.samples.append(sample)
    state.last_value_per_instance[sample.instance] = sample.v

    if sample.v >= target_gates:
        state.completed_instances[sample.instance] = sample.t
        state.instance_times[sample.instance]['end'] = sample.t

    return True

def trim_samples(state: PhaseState, window_sec: float) -> None:
    if not state.samples:
        return

    recent_samples = state.samples[-min(len(state.samples), 100):]
    if not recent_samples:
        return

    cutoff = recent_samples[-1].t - max(window_sec * 5, 300)

    if cutoff <= 0:
        return

    filtered = []
    for sample in state.samples:
        if sample.t >= cutoff or sample.instance not in state.completed_instances:
            filtered.append(sample)

    state.samples = filtered

def choose_active_phase(current_phase: str, last_activity: Dict[str, float]) -> str:
    candidates = [
        (last_activity.get(phase, 0.0), PHASE_ORDER_INDEX[phase], phase)
        for phase in PHASES
    ]
    best_time, _, best_phase = max(candidates)
    if best_time <= 0:
        fallback = current_phase if last_activity.get(current_phase, 0.0) > 0 else 'garbling'
        return fallback
    return best_phase

def build_phase_summary(phase: str, state: PhaseState, target_gates: int) -> str:
    if not state.samples and not state.completed_instances:
        return "pending"

    if phase == 'evaluation':
        if not state.samples:
            return "pending"
        latest = state.samples[-1]
        return f"{fmt_gates(latest.v)} processed"

    total_instances = state.expected_total
    if total_instances is None and state.max_instance_id >= 0:
        total_instances = state.max_instance_id + 1

    completed = len(state.completed_instances)

    if total_instances and completed >= total_instances:
        return f"completed {completed}/{total_instances}"

    if not state.samples:
        if total_instances:
            return f"{completed}/{total_instances} completed"
        return f"{completed} completed"

    latest = state.samples[-1]
    progress_pct = (latest.v / target_gates) * 100 if target_gates else 0.0
    inst_blurb = f"inst {latest.instance}: {progress_pct:5.1f}%"

    if total_instances:
        return f"{completed}/{total_instances} done · {inst_blurb}"
    return f"{completed} done · {inst_blurb}"

def print_auto_status(
    active_phase: str,
    phase_states: Dict[str, PhaseState],
    target_gates: int,
    window_sec: float,
) -> None:
    global MODE
    state = phase_states[active_phase]

    if state.samples:
        previous_mode = MODE
        MODE = active_phase
        try:
            print_status(
                state.samples,
                target_gates,
                window_sec,
                state.completed_instances,
                state.instance_times,
                state.expected_total,
                state.max_instance_id,
            )
        finally:
            MODE = previous_mode
    else:
        # No samples yet for the active phase; emit a lightweight placeholder.
        print("\033[2J\033[H")
        print("=" * 80)
        print("CUT-AND-CHOOSE MONITOR (auto phase detection)")
        print("=" * 80)
        print(f"Awaiting data for {PHASE_LABELS[active_phase]} ...")

    print("\n" + "=" * 70)
    print("PHASE OVERVIEW:")
    for phase in PHASES:
        marker = "*" if phase == active_phase else " "
        summary = build_phase_summary(phase, phase_states[phase], target_gates)
        label = PHASE_LABELS[phase]
        print(f" {marker} {label:12s} {summary}")

    sys.stdout.flush()

def tail_file_auto(path: str, target_gates: int, window_sec: float) -> None:
    phase_states = {phase: PhaseState() for phase in PHASES}
    last_activity = {phase: 0.0 for phase in PHASES}
    active_phase = 'garbling'
    detected_creating = False
    detected_instances = False
    detected_garbler_line = False

    def open_file():
        return open(path, 'r', encoding='utf-8', errors='ignore')

    def reset_state():
        nonlocal phase_states, last_activity, active_phase
        nonlocal detected_creating, detected_instances, detected_garbler_line
        phase_states = {phase: PhaseState() for phase in PHASES}
        last_activity = {phase: 0.0 for phase in PHASES}
        active_phase = 'garbling'
        detected_creating = False
        detected_instances = False
        detected_garbler_line = False

    def handle_metadata(line: str) -> bool:
        nonlocal detected_creating, detected_instances, detected_garbler_line
        updated = False

        if "Garbler: Creating" in line:
            m2 = re.search(r'Creating\s+(\d+)\s+instances\s*\((\d+)\s+to finalize\)', line)
            if m2:
                total = int(m2.group(1))
                to_finalize = int(m2.group(2))
                for phase in ("garbling", "regarbling"):
                    phase_states[phase].expected_total = total
                if not detected_creating:
                    print(
                        f"Detected instances from 'Creating': total={total}, to_finalize={to_finalize}",
                        file=sys.stderr,
                    )
                    detected_creating = True
                updated = True

        if "Garbler:" in line and not detected_garbler_line:
            m3 = re.search(r'Garbler:\s+(\d+)\s*/\s*(\d+)', line)
            if m3:
                total = int(m3.group(1))
                to_finalize = int(m3.group(2))
                for phase in ("garbling", "regarbling"):
                    phase_states[phase].expected_total = total
                if phase_states['evaluation'].expected_total is None:
                    phase_states['evaluation'].expected_total = total
                print(
                    f"Detected instances from 'Garbler:' line: total={total}, to_finalize={to_finalize}",
                    file=sys.stderr,
                )
                detected_garbler_line = True
                updated = True

        if "Starting cut-and-choose with" in line and not detected_instances:
            m = re.search(r'with\s+(\d+)\s+instances', line)
            if m:
                expected_total = int(m.group(1))
                for phase in ("garbling", "regarbling"):
                    if phase_states[phase].expected_total is None:
                        phase_states[phase].expected_total = expected_total
                phase_states['evaluation'].expected_total = expected_total
                print(f"Detected {expected_total} total instances from log", file=sys.stderr)
                detected_instances = True
                updated = True

        return updated

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
        handle_metadata(line)
        sample = parse_line(line.strip())
        if sample is None:
            continue
        state = phase_states[sample.phase]
        appended = process_sample(state, sample, target_gates, ignore_non_increasing=True)
        if appended:
            last_activity[sample.phase] = sample.t
            active_phase = choose_active_phase(active_phase, last_activity)

    pos = f.tell()
    print_auto_status(active_phase, phase_states, target_gates, window_sec)

    # Live monitoring loop
    while True:
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

            while True:
                try:
                    f = open_file()
                    break
                except FileNotFoundError:
                    time.sleep(0.5)

            f_stat = os.fstat(f.fileno())
            inode = f_stat.st_ino
            reset_state()

            while True:
                line = f.readline()
                if not line:
                    break
                handle_metadata(line)
                sample = parse_line(line.strip())
                if sample is None:
                    continue
                state = phase_states[sample.phase]
                appended = process_sample(state, sample, target_gates, ignore_non_increasing=True)
                if appended:
                    last_activity[sample.phase] = sample.t
                    active_phase = choose_active_phase(active_phase, last_activity)

            pos = f.tell()
            print_auto_status(active_phase, phase_states, target_gates, window_sec)
            time.sleep(0.3)
            continue

        line = f.readline()
        if not line:
            time.sleep(0.3)
            continue

        pos = f.tell()
        metadata_changed = handle_metadata(line)
        sample = parse_line(line.strip())
        if sample is None:
            if metadata_changed:
                print_auto_status(active_phase, phase_states, target_gates, window_sec)
            continue

        state = phase_states[sample.phase]
        appended = process_sample(state, sample, target_gates, ignore_non_increasing=False)
        if appended:
            last_activity[sample.phase] = sample.t
            active_phase = choose_active_phase(active_phase, last_activity)
            trim_samples(state, window_sec)

        if appended or metadata_changed:
            print_auto_status(active_phase, phase_states, target_gates, window_sec)

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
    phase = PHASE_LABELS.get(MODE, MODE.upper())

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
    if MODE == "auto":
        tail_file_auto(path, target_gates, window_sec)
        return

    state = PhaseState()

    def open_file():
        return open(path, 'r', encoding='utf-8', errors='ignore')

    def handle_metadata(line: str) -> None:
        if MODE == "evaluation":
            return

        if "Garbler: Creating" in line:
            m2 = re.search(r'Creating\s+(\d+)\s+instances\s*\((\d+)\s+to finalize\)', line)
            if m2:
                total = int(m2.group(1))
                to_finalize = int(m2.group(2))
                state.expected_total = total
                print(
                    f"Detected instances from 'Creating': total={total}, to_finalize={to_finalize}, expected_total={state.expected_total}",
                    file=sys.stderr,
                )

        if state.expected_total is None and "Starting cut-and-choose with" in line:
            m = re.search(r'with (\d+) instances', line)
            if m:
                state.expected_total = int(m.group(1))
                print(f"Detected {state.expected_total} total instances from log", file=sys.stderr)

        if state.expected_total is None and "Garbler:" in line:
            m = re.search(r'Garbler:\s+(\d+)\s*/\s*(\d+)', line)
            if m:
                total = int(m.group(1))
                to_finalize = int(m.group(2))
                state.expected_total = total
                print(
                    f"Detected instances from 'Garbler:' line: total={total}, to_finalize={to_finalize}",
                    file=sys.stderr,
                )

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
        handle_metadata(line)
        sample = parse_line(line.strip())
        if sample is None:
            continue

        process_sample(state, sample, target_gates, ignore_non_increasing=True)

    pos = f.tell()
    if state.samples:
        print_status(
            state.samples,
            target_gates,
            window_sec,
            state.completed_instances,
            state.instance_times,
            state.expected_total,
            state.max_instance_id,
        )

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
            state = PhaseState()
            while True:
                line = f.readline()
                if not line:
                    break
                handle_metadata(line)
                sample = parse_line(line.strip())
                if sample is None:
                    continue
                process_sample(state, sample, target_gates, ignore_non_increasing=True)
            pos = f.tell()
            if state.samples:
                print_status(
                    state.samples,
                    target_gates,
                    window_sec,
                    state.completed_instances,
                    state.instance_times,
                    state.expected_total,
                    state.max_instance_id,
                )
            time.sleep(0.3)
            continue

        # Read any new lines
        line = f.readline()
        if not line:
            time.sleep(0.3)
            continue
        pos = f.tell()
        handle_metadata(line)
        sample = parse_line(line.strip())
        if sample is None:
            continue

        appended = process_sample(state, sample, target_gates, ignore_non_increasing=False)
        if appended:
            trim_samples(state, window_sec)

        if state.samples:
            print_status(
                state.samples,
                target_gates,
                window_sec,
                state.completed_instances,
                state.instance_times,
                state.expected_total,
                state.max_instance_id,
            )

def main():
    global MODE
    parser = argparse.ArgumentParser(
        description="Live monitor for garbling/regarbling/evaluation logs"
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default="2from3.log",
        help="Path to the log file to follow (default: 2from3.log)",
    )
    parser.add_argument(
        "--garbling",
        action="store_true",
        help="Track only the initial garbling phase (previous default)",
    )
    parser.add_argument(
        "--regarbling",
        action="store_true",
        help="Track regarbling flow (match 'regarble: garbled: ...')",
    )
    parser.add_argument(
        "--evaluation",
        action="store_true",
        help="Track evaluation throughput (match 'evaluated: ...')",
    )
    args = parser.parse_args()

    # Determine mode (mutually exclusive flags)
    selected = sum(bool(x) for x in (args.garbling, args.regarbling, args.evaluation))
    if selected > 1:
        print("Use only one of --garbling, --regarbling, or --evaluation", file=sys.stderr)
        sys.exit(2)

    if args.evaluation:
        MODE = "evaluation"
    elif args.regarbling:
        MODE = "regarbling"
    elif args.garbling:
        MODE = "garbling"
    else:
        MODE = "auto"

    window_sec = float(os.environ.get("WINDOW_SEC", "30"))
    # Fixed target: each Groth16 instance requires exactly this many gates
    target_gates = 11_174_708_821

    try:
        tail_file(args.logfile, target_gates, window_sec)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)

if __name__ == "__main__":
    main()
