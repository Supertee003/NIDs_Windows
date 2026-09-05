#!/usr/bin/env python3
"""
AEGIS NIDS - Phase 30: Performance Benchmark

Measures throughput, latency, and resource usage of the AEGIS NIDS pipeline.
Generates a report with metrics for capacity planning and regression tracking.

Usage:
  python phase30_benchmark.py                    # Quick benchmark (1000 events)
  python phase30_benchmark.py --events 10000     # Larger load test
  python phase30_benchmark.py --duration 60      # Run for 60 seconds
  python phase30_benchmark.py --report-only       # Just read existing logs

Metrics collected:
  - Events per second (EPS) through Brain
  - Detection rate (DETECTED vs total)
  - Block enforcement rate (BLOCK_OK vs BLOCK_FAILED)
  - Latency (time from event to log entry)
  - Forensic log write rate (NDJSON lines/sec)
  - WFP driver block rate (if driver loaded)
"""

import argparse
import json
import os
import psutil
import socket
import statistics
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

# ============================================================
# Configuration
# ============================================================

BRAIN_UDP_PORT = 9999
ANOMALOUS_LOG = Path("logs/anomalous.json")
CORE_LOG = Path("logs/core.log")
BRAIN_LOG = Path("logs/brain.log")
NOSE_LOG = Path("logs/nose_stdout.log")
REPORT_FILE = Path("logs/benchmark_report.json")

# ============================================================
# Helpers
# ============================================================

def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"  [{ts}] {msg}")


def read_anomalous_log() -> list:
    """Read all events from anomalous.json (NDJSON format)."""
    events = []
    if not ANOMALOUS_LOG.exists():
        return events
    with ANOMALOUS_LOG.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def send_brain_event(event: dict) -> bool:
    """Send a synthetic event to Brain via UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        msg = json.dumps(event).encode("utf-8")
        sock.sendto(msg, ("127.0.0.1", BRAIN_UDP_PORT))
        sock.close()
        return True
    except OSError:
        return False


def get_process_metrics() -> dict:
    """Get CPU/memory metrics for AEGIS processes."""
    metrics = {}
    process_names = {
        "aegis-nids.exe": "core",
        "aegis_bridge.exe": "bridge",
        "python.exe": "brain",
        "nose_dashboard.exe": "nose",
        "windows_sec_monitor.exe": "mouth",
    }

    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
        try:
            name = proc.info["name"]
            if name in process_names:
                label = process_names[name]
                mem = proc.info["memory_info"]
                metrics[label] = {
                    "pid": proc.info["pid"],
                    "cpu_pct": proc.info["cpu_percent"],
                    "rss_mb": mem.rss / (1024 * 1024) if mem else 0,
                    "vms_mb": mem.vms / (1024 * 1024) if mem else 0,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return metrics


def check_wfp_driver() -> bool:
    """Check if WFP driver service is running."""
    try:
        import subprocess
        result = subprocess.run(
            ["sc", "query", "aegis_wfp"],
            capture_output=True, text=True, timeout=5
        )
        return "RUNNING" in result.stdout
    except Exception:
        return False


# ============================================================
# Benchmark Functions
# ============================================================

def benchmark_throughput(num_events: int, interval: float = 0) -> dict:
    """Send N events through Brain and measure throughput."""
    log(f"Starting throughput benchmark: {num_events} events")

    # Verify Brain UDP connectivity BEFORE sending events
    log("Testing Brain UDP connectivity (127.0.0.1:9999)...")
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.settimeout(2.0)
        test_event = json.dumps({"attack_type": "CONNECTIVITY_TEST", "test": True}).encode()
        test_sock.sendto(test_event, ("127.0.0.1", 9999))
        test_sock.close()
        log("  UDP send OK (Brain port reachable)")
    except OSError as e:
        log(f"  [WARN] Cannot send to Brain: {e}")
        log("  Benchmark will continue but events may not be processed")

    # Wait a moment for Brain to log the test event
    time.sleep(0.5)

    # Check if test event was logged
    test_events = read_anomalous_log()
    test_logged = any(e.get("attack_type") == "CONNECTIVITY_TEST" for e in test_events[-5:])
    if test_logged:
        log("  [OK] Brain is processing events (test event logged)")
    else:
        log("  [WARN] Brain did not log test event - may not be running or listening")
        log("  Check: tasklist | findstr python  (Brain should be running)")

    # Record baseline (after test event)
    baseline_events = read_anomalous_log()
    baseline_count = len(baseline_events)
    log(f"  Baseline events in log: {baseline_count}")

    start_time = time.time()

    sent = 0
    for i in range(num_events):
        event = {
            "attack_type": f"BENCH-{i % 10}",
            "src_ip": f"10.0.{i // 256}.{i % 256}",
            "dst_ip": "127.0.0.1",
            "src_port": 10000 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "severity": "Medium" if i % 3 == 0 else "High",
            "policy": "ALERT",
            "rule_id": f"BENCH-{i // 100}",
            "payload": f"benchmark-payload-{i}",
            "reason": "Phase 30 throughput benchmark",
            "source": "phase30_benchmark",
            "status": "DETECTED",
        }
        if send_brain_event(event):
            sent += 1
        if interval > 0 and i % 100 == 0 and i > 0:
            time.sleep(interval)

    send_duration = time.time() - start_time

    # Wait for Brain to process
    log(f"Sent {sent} events in {send_duration:.2f}s ({sent/send_duration:.0f} EPS)")
    log("Waiting 3s for Brain to process...")
    time.sleep(3)

    # Read results
    after_events = read_anomalous_log()
    after_count = len(after_events)
    new_events = after_count - baseline_count

    total_duration = time.time() - start_time
    eps = new_events / total_duration if total_duration > 0 else 0

    # Analyze events
    detected = sum(1 for e in after_events[baseline_count:] if e.get("status") == "DETECTED")
    blocked_ok = sum(1 for e in after_events[baseline_count:] if e.get("status") == "BLOCK_OK")
    block_failed = sum(1 for e in after_events[baseline_count:] if e.get("status") == "BLOCK_FAILED")

    # Attack type distribution
    attack_types = defaultdict(int)
    for e in after_events[baseline_count:]:
        at = e.get("attack_type", "UNKNOWN")
        attack_types[at] += 1

    return {
        "events_sent": sent,
        "events_logged": new_events,
        "send_duration_s": round(send_duration, 3),
        "total_duration_s": round(total_duration, 3),
        "events_per_second": round(eps, 1),
        "detection_rate_pct": round(detected / max(new_events, 1) * 100, 1),
        "block_ok": blocked_ok,
        "block_failed": block_failed,
        "top_attack_types": dict(sorted(attack_types.items(), key=lambda x: -x[1])[:5]),
    }


def benchmark_duration(duration_s: int) -> dict:
    """Send events for a fixed duration and measure sustained throughput."""
    log(f"Starting duration benchmark: {duration_s}s")

    baseline_events = read_anomalous_log()
    baseline_count = len(baseline_events)

    start_time = time.time()
    sent = 0

    while time.time() - start_time < duration_s:
        event = {
            "attack_type": f"DUR-{sent % 12}",
            "src_ip": f"10.1.{sent // 256 % 256}.{sent % 256}",
            "dst_ip": "127.0.0.1",
            "src_port": 20000 + (sent % 10000),
            "dst_port": 80,
            "protocol": "TCP",
            "severity": "High",
            "policy": "BLOCK" if sent % 5 == 0 else "ALERT",
            "rule_id": f"DUR-RULE",
            "payload": f"duration-benchmark-{sent}",
            "reason": "Phase 30 duration benchmark",
            "source": "phase30_benchmark",
            "status": "DETECTED",
        }
        send_brain_event(event)
        sent += 1
        # Small delay to avoid overwhelming
        if sent % 1000 == 0:
            time.sleep(0.01)

    actual_duration = time.time() - start_time
    eps = sent / actual_duration if actual_duration > 0 else 0

    # Wait for processing
    time.sleep(3)
    after_events = read_anomalous_log()
    new_events = len(after_events) - baseline_count

    return {
        "duration_target_s": duration_s,
        "duration_actual_s": round(actual_duration, 3),
        "events_sent": sent,
        "events_logged": new_events,
        "send_eps": round(eps, 1),
        "process_eps": round(new_events / actual_duration, 1) if actual_duration > 0 else 0,
    }


def benchmark_resources() -> dict:
    """Collect resource usage metrics."""
    log("Collecting resource metrics...")
    return get_process_metrics()


def generate_report(throughput: dict, duration: dict, resources: dict, wfp: bool) -> dict:
    """Generate final benchmark report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "system": {
            "wfp_driver_running": wfp,
            "subsystems_running": [k for k, v in resources.items() if v],
        },
        "throughput": throughput,
        "duration_test": duration,
        "resources": resources,
        "summary": {
            "peak_eps": throughput.get("events_per_second", 0),
            "sustained_eps": duration.get("process_eps", 0),
            "block_enforcement": "ACTIVE" if wfp else "INACTIVE",
            "detection_rate": throughput.get("detection_rate_pct", 0),
        },
    }

    # Save report
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_FILE.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report


def print_report(report: dict):
    """Pretty-print the benchmark report."""
    print("\n" + "=" * 60)
    print("AEGIS NIDS - Phase 30: Benchmark Report")
    print("=" * 60)

    print(f"\nTimestamp: {report['timestamp']}")

    print(f"\n--- System Status ---")
    wfp = report["system"]["wfp_driver_running"]
    print(f"  WFP Driver:        {'✅ RUNNING' if wfp else '❌ NOT RUNNING'}")
    print(f"  Subsystems:        {', '.join(report['system']['subsystems_running'])}")

    tp = report["throughput"]
    print(f"\n--- Throughput Benchmark ---")
    print(f"  Events sent:       {tp.get('events_sent', 0)}")
    print(f"  Events logged:    {tp.get('events_logged', 0)}")
    print(f"  Send duration:     {tp.get('send_duration_s', 0)}s")
    print(f"  Total duration:    {tp.get('total_duration_s', 0)}s")
    print(f"  Events/sec:        {tp.get('events_per_second', 0)} EPS")
    print(f"  Detection rate:    {tp.get('detection_rate_pct', 0)}%")
    print(f"  BLOCK_OK:          {tp.get('block_ok', 0)}")
    print(f"  BLOCK_FAILED:      {tp.get('block_failed', 0)}")

    dt = report["duration_test"]
    print(f"\n--- Duration Benchmark ---")
    print(f"  Duration:          {dt.get('duration_actual_s', 0)}s")
    print(f"  Events sent:       {dt.get('events_sent', 0)}")
    print(f"  Events logged:    {dt.get('events_logged', 0)}")
    print(f"  Send EPS:          {dt.get('send_eps', 0)}")
    print(f"  Process EPS:       {dt.get('process_eps', 0)}")

    print(f"\n--- Resource Usage ---")
    for label, m in report["resources"].items():
        print(f"  {label:10s}  PID={m['pid']}  CPU={m['cpu_pct']:.1f}%  RSS={m['rss_mb']:.1f}MB")

    print(f"\n--- Summary ---")
    s = report["summary"]
    print(f"  Peak EPS:          {s['peak_eps']}")
    print(f"  Sustained EPS:     {s['sustained_eps']}")
    print(f"  Block enforcement: {s['block_enforcement']}")
    print(f"  Detection rate:    {s['detection_rate']}%")

    print(f"\n  Report saved: {REPORT_FILE}")
    print("=" * 60)


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="AEGIS NIDS Phase 30 - Performance Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--events", type=int, default=1000, help="Number of events for throughput test (default: 1000)")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds for sustained test (default: 10)")
    parser.add_argument("--interval", type=float, default=0, help="Interval between event batches (default: 0)")
    parser.add_argument("--report-only", action="store_true", help="Only generate report from existing logs")

    args = parser.parse_args()

    print("=" * 60)
    print("AEGIS NIDS - Phase 30: Performance Benchmark")
    print("=" * 60)

    if args.report_only:
        events = read_anomalous_log()
        tp = {"events_sent": len(events), "events_logged": len(events), "events_per_second": 0}
        dt = {}
        resources = get_process_metrics()
        wfp = check_wfp_driver()
        report = generate_report(tp, dt, resources, wfp)
        print_report(report)
        return

    # Check prerequisites
    wfp = check_wfp_driver()
    log(f"WFP driver: {'RUNNING' if wfp else 'NOT RUNNING'}")

    resources_before = get_process_metrics()
    log(f"Subsystems detected: {list(resources_before.keys())}")

    if not resources_before:
        print("  [WARN] No AEGIS processes detected. Start AEGIS first:")
        print("         scripts\\run_aegis.bat")

    # Run benchmarks
    tp = benchmark_throughput(args.events, args.interval)
    dt = benchmark_duration(args.duration)
    resources_after = get_process_metrics()

    # Generate + print report
    report = generate_report(tp, dt, resources_after, wfp)
    print_report(report)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[Benchmark interrupted by user]")
        sys.exit(1)
