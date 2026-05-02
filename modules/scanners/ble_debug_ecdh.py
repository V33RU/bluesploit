"""
BlueSploit Scanner: BLE Debug ECDH Key Detection

The Bluetooth Core Specification publishes a fixed pair of debug ECDH keys
intended for testing implementations. Production firmware should NEVER use
these keys — but firmware/config bugs sometimes ship them, completely
breaking BLE Secure Connections security.

If a device uses the debug DH key pair during pairing, anyone with the
corresponding (public) debug private key can derive the session LTK and
decrypt all subsequent traffic. The debug key has been published by the
Bluetooth SIG and is widely known.

Debug Public Key (X || Y) — from Bluetooth Core Spec v5.0+:
  X = 20 B0 03 D2 F2 97 BE 2C 5E 2C 83 A7 E9 F9 A5 B9
      EF F4 91 11 AC F4 FD DB CC 03 01 48 0E 35 9D E6
  Y = DC 80 9C 49 65 2A EB 6D 63 32 9A BF 5A 52 15 5C
      76 63 45 C2 8F ED 30 24 74 1C 8E D0 15 89 D2 8B

Debug Private Key (corresponding):
  3F 49 F6 D4 A3 C5 5F 38 74 C9 B3 E3 D2 10 3F 50
  4A FF 60 7B EB 40 B7 99 58 99 B8 A6 CD 5C 9A 7B

Modes:
  detect    — Sniff or actively probe pairings, alert on debug key usage
  exploit   — When debug key detected: derive LTK, attach to session
  audit     — Static check on captured PCAP for debug key presence

Reference: BT Core Specification v5.0 Vol. 6, Part E, §7.1.5.1
"""

import asyncio
import os
import re
import struct
import subprocess
import time
from typing import List, Optional, Dict
from core.base import ScannerModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)


# Bluetooth SIG debug ECDH public key (P-256 X || Y)
DEBUG_PUBKEY_X = bytes.fromhex(
    "20B003D2F297BE2C5E2C83A7E9F9A5B9"
    "EFF49111ACF4FDDBCC0301480E359DE6"
)
DEBUG_PUBKEY_Y = bytes.fromhex(
    "DC809C49652AEB6D63329ABF5A52155C"
    "766345C28FED3024741C8ED01589D28B"
)

DEBUG_PRIVKEY = bytes.fromhex(
    "3F49F6D4A3C55F3874C9B3E3D2103F50"
    "4AFF607BEB40B7995899B8A6CD5C9A7B"
)


def _is_debug_pubkey(pubkey_bytes: bytes) -> bool:
    """Check if a pubkey matches the published BT debug key."""
    if len(pubkey_bytes) < 64:
        return False
    x = pubkey_bytes[:32]
    y = pubkey_bytes[32:64]
    return x == DEBUG_PUBKEY_X and y == DEBUG_PUBKEY_Y


def _is_debug_pubkey_x_only(x: bytes) -> bool:
    """Check just the X coordinate (some captures only have X)."""
    return x[:32] == DEBUG_PUBKEY_X


class Module(ScannerModule):
    """
    BLE Debug ECDH Key Detector

    Detects Bluetooth devices using the well-known SIG debug ECDH key pair.
    Production firmware using this key has zero ECDH security.
    """

    info = ModuleInfo(
        name="BLE Debug ECDH Key Detection",
        description=(
            "Detect Bluetooth devices that use the published BT SIG debug "
            "ECDH key pair — production-broken Secure Connections"
        ),
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.HIGH,
        cve=None,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification-5-3/",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-5383",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="mode",
            required=True,
            description="Mode: detect, exploit, audit",
            default="detect",
        ))
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="Target BD_ADDR (detect/exploit) or 'any' for broadcast scan",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="pcap_file",
            required=False,
            description="PCAP to audit (audit mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="Local HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Sniff duration in seconds (detect mode)",
            default=120,
        ))

    def run(self) -> bool:
        mode = (self.get_option("mode") or "detect").lower()

        C = Colors
        print(f"\n  {C.RED}╔{'═'*58}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}BLE Debug ECDH Key Detection{C.RESET}                             {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*58}╝{C.RESET}\n")

        print_info(f"Mode        : {mode}")
        print_info(f"Debug pubkey X: {DEBUG_PUBKEY_X[:8].hex()}…")
        print_warning("DISCLAIMER: For authorized security testing only!")

        if mode == "detect":
            return self._detect()
        if mode == "exploit":
            return self._exploit()
        if mode == "audit":
            return self._audit(self.get_option("pcap_file"))
        return False

    def _detect(self) -> bool:
        """Sniff SMP Pairing Public Key PDUs and compare against debug key."""
        if os.geteuid() != 0:
            print_error("Root required for HCI sniff")
            return False

        adapter = self.get_option("interface") or "hci0"
        duration = int(self.get_option("duration") or 120)
        target = self.get_option("target")

        print_info(f"\nSniffing SMP Pairing Public Keys for {duration}s...")
        print_info("Trigger pairing on target device(s) now")

        # Use btmon to capture and grep for SMP pubkey patterns
        btmon_log = f"/tmp/blesploit_btmon_{int(time.time())}.log"
        try:
            proc = subprocess.Popen(
                ["btmon", "-w", btmon_log],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            print_success(f"btmon capturing to {btmon_log}")
            try:
                time.sleep(duration)
            except KeyboardInterrupt:
                print_warning("\nStopped early")
            proc.terminate()
            proc.wait(timeout=5)
        except FileNotFoundError:
            print_error("btmon not found — install bluez-tools")
            return False

        # Parse btmon log for SMP Pairing Public Key (opcode 0x0c)
        return self._audit(btmon_log)

    def _exploit(self) -> bool:
        """When debug key detected, derive shared secret using known privkey."""
        target = self.get_option("target")
        if not target or not self.validate_bd_addr(target):
            print_error("exploit mode requires valid target BD_ADDR")
            return False

        print_info(f"\nAttempting to derive LTK using debug private key...")
        print_info(f"Debug priv (16B prefix): {DEBUG_PRIVKEY[:16].hex()}")
        print_warning("Real exploit requires capturing peer pubkey first via _detect()")

        # Demonstrate ECDH derivation with debug key
        try:
            from cryptography.hazmat.primitives.asymmetric.ec import (
                ECDH, EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers, SECP256R1
            )
            curve = SECP256R1()
            priv_int = int.from_bytes(DEBUG_PRIVKEY, "big")
            pub_x = int.from_bytes(DEBUG_PUBKEY_X, "big")
            pub_y = int.from_bytes(DEBUG_PUBKEY_Y, "big")
            priv_key = EllipticCurvePrivateNumbers(
                priv_int,
                EllipticCurvePublicNumbers(pub_x, pub_y, curve),
            ).private_key()
            print_success("Loaded debug ECDH private key on P-256")

            # Self-derive shared (for demonstration)
            pub_key = priv_key.public_key()
            shared = priv_key.exchange(ECDH(), pub_key)
            print_success(f"Self-ECDH shared (32B): {shared.hex()}")
            print_info("In real attack: use peer's captured pubkey here")

            self.add_result({
                "mode": "exploit",
                "target": target,
                "debug_key_loaded": True,
                "self_ecdh_demonstration": shared.hex(),
            })
            return True
        except ImportError:
            print_error("cryptography required — pip install cryptography")
            return False
        except Exception as e:
            print_error(f"ECDH error: {e}")
            return False

    def _audit(self, pcap_or_log: Optional[str]) -> bool:
        """Static audit: search a btmon log or PCAP for the debug pubkey."""
        if not pcap_or_log or not os.path.isfile(pcap_or_log):
            print_error("audit requires existing pcap_file / log")
            return False

        print_info(f"\nAuditing {pcap_or_log} for debug ECDH key...")
        try:
            with open(pcap_or_log, "rb") as f:
                content = f.read()
        except OSError as e:
            print_error(f"Cannot read: {e}")
            return False

        # Search for debug pubkey X coordinate in raw bytes
        hits = []
        offset = 0
        while True:
            idx = content.find(DEBUG_PUBKEY_X, offset)
            if idx < 0:
                break
            hits.append(idx)
            offset = idx + 32

        if hits:
            print_warning(f"DEBUG ECDH KEY FOUND at {len(hits)} offset(s):")
            for h in hits[:10]:
                print_warning(f"  byte offset 0x{h:08X}")
            print_warning("Affected pairings have ZERO ECDH security")
            self.add_result({
                "mode": "audit",
                "file": pcap_or_log,
                "debug_key_hits": len(hits),
                "vulnerable": True,
            })
            return True

        # Also check for X coordinate as ASCII hex (in case file is text/log)
        x_hex = DEBUG_PUBKEY_X.hex()
        text_hits = []
        try:
            text = content.decode("utf-8", errors="ignore")
            for m in re.finditer(re.escape(x_hex), text, re.IGNORECASE):
                text_hits.append(m.start())
        except Exception:
            pass

        if text_hits:
            print_warning(f"Debug key found as hex string at {len(text_hits)} location(s)")
            self.add_result({
                "mode": "audit",
                "file": pcap_or_log,
                "debug_key_hits_text": len(text_hits),
                "vulnerable": True,
            })
            return True

        print_success("No debug ECDH key found in capture — looks clean")
        self.add_result({
            "mode": "audit",
            "file": pcap_or_log,
            "debug_key_hits": 0,
            "vulnerable": False,
        })
        return False
