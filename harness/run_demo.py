#!/usr/bin/env python3
"""
AetherGuard Demo Harness
========================
Automated demo runner that loads exploit_samples.json, fires test payloads
against the AetherGuard proxy at http://localhost:8080/v1/tools/verify,
and pauses between tests so judges can watch the 3D dashboard update in real time.

Usage:
    python harness/run_demo.py
"""

import json
import os
import sys
import time
import requests

PROXY_URL = os.getenv("AETHERGUARD_PROXY_URL", "http://localhost:8080")
VERIFY_ENDPOINT = f"{PROXY_URL}/v1/tools/verify"
PAUSE_SECONDS = 3

# ANSI color codes for CLI formatting
COLORS = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN": "\033[96m",
    "MAGENTA": "\033[95m",
    "WHITE": "\033[97m",
    "BG_RED": "\033[41m",
    "BG_GREEN": "\033[42m",
    "BG_CYAN": "\033[46m",
}


def print_banner():
    """Print the AetherGuard demo banner."""
    banner = f"""
{COLORS['CYAN']}{COLORS['BOLD']}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     ▄▄▄      ▓█████ ▄▄▄█████▓ ██░ ██ ▓█████  ██▀███              ║
║    ▒████▄    ▓█   ▀ ▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒           ║
║    ▒██  ▀█▄  ▒███   ▒ ▓██░ ▒░▒██▀▀██░▒███   ▓██ ░▄█ ▒           ║
║    ░██▄▄▄▄██ ▒▓█  ▄ ░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄             ║
║     ▓█   ▓██▒░▒████▒  ▒██▒ ░ ░▓█▒░██▓░▒████▒░██▓ ▒██▒           ║
║     ▒▒   ▓▒█░░░ ▒░ ░  ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░           ║
║      ▒   ▒▒ ░ ░ ░  ░    ░     ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░           ║
║                        G U A R D                                  ║
║                                                                  ║
║    Zero-Trust Runtime Security Proxy for Autonomous AI Agents     ║
║    NVIDIA x Nebius AI Hackathon │ Dual-Tier Cascade Defense       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝{COLORS['RESET']}
"""
    print(banner)


def print_case_header(case):
    """Print formatted header for a test case."""
    case_id = case["case_id"]
    name = case["name"]
    expected = case["expected_verdict"]
    expected_tier = case.get("expected_tier", "unknown")

    color = COLORS["GREEN"] if expected == "AUTHORIZED" else COLORS["RED"]
    print(f"\n{COLORS['CYAN']}{'═' * 68}{COLORS['RESET']}")
    print(f"{COLORS['BOLD']}{COLORS['WHITE']}  CASE {case_id}/5 │ {name}{COLORS['RESET']}")
    print(f"{COLORS['DIM']}  {case['description']}{COLORS['RESET']}")
    print(f"  {COLORS['YELLOW']}Expected:{COLORS['RESET']} {color}{COLORS['BOLD']}{expected}{COLORS['RESET']}  │  Tier: {COLORS['MAGENTA']}{expected_tier}{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}{'─' * 68}{COLORS['RESET']}")

    # Print payload details
    payload = case["payload"]
    print(f"  {COLORS['DIM']}Tool:{COLORS['RESET']}   {payload['tool_name']}")
    cmd = payload["tool_args"].get("command") or payload["tool_args"].get("query", "")
    print(f"  {COLORS['DIM']}Cmd:{COLORS['RESET']}    {COLORS['YELLOW']}{cmd}{COLORS['RESET']}")
    print(f"  {COLORS['DIM']}Intent:{COLORS['RESET']} \"{payload['declared_intent']}\"")


def print_result(result, latency_request_ms):
    """Print formatted result of a test case."""
    status_val = result.get("status", "UNKNOWN")
    tier = result.get("tier", "unknown")
    latency = result.get("latency_ms", 0)
    reason = result.get("reason", "")
    violation = result.get("violation", "")
    threat_type = result.get("threat_type", "")

    if status_val == "QUARANTINED" or status_val == "CIRCUIT_BROKEN":
        status_color = COLORS["RED"]
        bg_color = COLORS["BG_RED"]
        icon = "🛑"
    else:
        status_color = COLORS["GREEN"]
        bg_color = COLORS["BG_GREEN"]
        icon = "✅"

    print(f"\n  {icon}  {bg_color}{COLORS['BOLD']} {status_val} {COLORS['RESET']}")
    print(f"  {COLORS['DIM']}├─ Tier:{COLORS['RESET']}       {COLORS['MAGENTA']}{tier}{COLORS['RESET']}")
    print(f"  {COLORS['DIM']}├─ Latency:{COLORS['RESET']}    {COLORS['CYAN']}{latency}ms{COLORS['RESET']} (round-trip: {latency_request_ms:.1f}ms)")
    if violation:
        print(f"  {COLORS['DIM']}├─ Violation:{COLORS['RESET']}  {COLORS['YELLOW']}{violation}{COLORS['RESET']}")
    if threat_type:
        print(f"  {COLORS['DIM']}├─ Threat:{COLORS['RESET']}    {status_color}{threat_type}{COLORS['RESET']}")
    if reason:
        print(f"  {COLORS['DIM']}└─ Reason:{COLORS['RESET']}    {reason}")


def check_proxy_health():
    """Check if the AetherGuard proxy is running."""
    try:
        resp = requests.get(f"{PROXY_URL}/health", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            print(f"  {COLORS['GREEN']}✓ Proxy is healthy{COLORS['RESET']} │ Mode: {data.get('mode', 'unknown')} │ WS clients: {data.get('active_ws_connections', 0)}")
            return True
    except requests.exceptions.ConnectionError:
        pass
    print(f"  {COLORS['RED']}✗ Cannot reach AetherGuard proxy at {PROXY_URL}{COLORS['RESET']}")
    print(f"  {COLORS['YELLOW']}  Start the backend first: uvicorn backend.main:app --host 0.0.0.0 --port 8080{COLORS['RESET']}")
    return False


def load_exploit_samples():
    """Load exploit samples from JSON file."""
    # Search for exploit_samples.json relative to script or in backend/
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "backend", "exploit_samples.json"),
        os.path.join(os.path.dirname(__file__), "exploit_samples.json"),
        os.path.join("backend", "exploit_samples.json"),
        "exploit_samples.json",
    ]
    for path in candidates:
        abs_path = os.path.abspath(path)
        if os.path.isfile(abs_path):
            with open(abs_path, "r") as f:
                samples = json.load(f)
            print(f"  {COLORS['GREEN']}✓ Loaded {len(samples)} exploit samples from {abs_path}{COLORS['RESET']}")
            return samples
    print(f"  {COLORS['RED']}✗ exploit_samples.json not found{COLORS['RESET']}")
    sys.exit(1)


def run_demo():
    """Main demo execution loop."""
    print_banner()

    print(f"{COLORS['CYAN']}[INIT]{COLORS['RESET']} Pre-flight checks...")
    if not check_proxy_health():
        sys.exit(1)

    samples = load_exploit_samples()
    total = len(samples)
    passed = 0
    failed = 0

    print(f"\n{COLORS['CYAN']}[DEMO]{COLORS['RESET']} Starting {total}-vector attack simulation...")
    print(f"{COLORS['DIM']}       Open http://localhost:5173 to watch the 3D dashboard react in real time.{COLORS['RESET']}")

    for i, case in enumerate(samples):
        print_case_header(case)

        # Fire payload at proxy
        print(f"\n  {COLORS['CYAN']}⚡ Firing payload...{COLORS['RESET']}", end="", flush=True)
        try:
            start = time.perf_counter()
            resp = requests.post(
                VERIFY_ENDPOINT,
                json=case["payload"],
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            elapsed = (time.perf_counter() - start) * 1000
            result = resp.json()
            print(f" {COLORS['GREEN']}Done ({elapsed:.0f}ms round-trip){COLORS['RESET']}")
            print_result(result, elapsed)

            # Check if result matches expectation
            actual_verdict = result.get("status", "UNKNOWN")
            expected = case["expected_verdict"]
            if actual_verdict == expected:
                passed += 1
                print(f"\n  {COLORS['GREEN']}✓ PASS — Verdict matches expected: {expected}{COLORS['RESET']}")
            else:
                failed += 1
                print(f"\n  {COLORS['RED']}✗ FAIL — Expected {expected}, got {actual_verdict}{COLORS['RESET']}")

        except requests.exceptions.RequestException as e:
            failed += 1
            print(f" {COLORS['RED']}ERROR: {e}{COLORS['RESET']}")

        # Pause between tests for dashboard visibility
        if i < total - 1:
            print(f"\n  {COLORS['DIM']}⏳ Pausing {PAUSE_SECONDS}s for dashboard observation...{COLORS['RESET']}")
            time.sleep(PAUSE_SECONDS)

    # Summary
    print(f"\n{COLORS['CYAN']}{'═' * 68}{COLORS['RESET']}")
    print(f"{COLORS['BOLD']}{COLORS['WHITE']}  DEMO COMPLETE │ Results: {passed}/{total} passed, {failed}/{total} failed{COLORS['RESET']}")
    if failed == 0:
        print(f"  {COLORS['GREEN']}{COLORS['BOLD']}🎯 ALL VECTORS DETECTED CORRECTLY{COLORS['RESET']}")
    else:
        print(f"  {COLORS['YELLOW']}⚠  Some vectors did not match expected verdicts{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}{'═' * 68}{COLORS['RESET']}\n")


if __name__ == "__main__":
    run_demo()
