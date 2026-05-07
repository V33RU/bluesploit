"""
BlueSploit Module: BLE Vulnerability Scanner
Auto-detect BLE vulnerabilities including unauthenticated writes,
weak pairing, information disclosure, and known CVEs

"""

import asyncio
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity, Target
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

try:
    from bleak import BleakClient
    from bleak.exc import BleakError
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# Suffix shared by all 16-bit Bluetooth SIG UUIDs when expressed as 128-bit
_BT_SIG_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def _short_uuid(uuid: str) -> str:
    """Return the 4-char hex short UUID for a BT SIG 16-bit UUID, or '' for vendor UUIDs."""
    u = uuid.lower()
    # Standard form: 0000xxxx-0000-1000-8000-00805f9b34fb
    if u.startswith("0000") and u.endswith(_BT_SIG_SUFFIX):
        return u[4:8]
    # Some stacks emit a bare 16-bit hex string (e.g. "ffe0")
    if len(u) == 4:
        return u
    return ""


class VulnSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    name: str
    severity: VulnSeverity
    description: str
    affected: str
    details: str
    recommendation: str
    cve: Optional[str] = None


@dataclass
class ScanResult:
    address: str
    name: str
    vulns: List[Vulnerability] = field(default_factory=list)
    services_count: int = 0
    chars_count: int = 0
    writable_count: int = 0
    notify_count: int = 0
    unauth_write_count: int = 0
    info_leak_count: int = 0


# Known vulnerable service patterns (short 16-bit UUID → metadata)
VULN_PATTERNS: Dict[str, Dict] = {
    "ffe0": {"name": "Common IoT Service (FFE0)",       "risk": "Often has unauthenticated writes",                   "severity": VulnSeverity.HIGH},
    "fff0": {"name": "Vendor Service (FFF0)",            "risk": "Custom protocol — verify authentication",            "severity": VulnSeverity.MEDIUM},
    "ffd0": {"name": "Vendor Service (FFD0)",            "risk": "Custom protocol — verify authentication",            "severity": VulnSeverity.MEDIUM},
    "fee0": {"name": "Xiaomi Service (FEE0)",            "risk": "Known unauthenticated write vulnerabilities",        "severity": VulnSeverity.HIGH},
    "fe59": {"name": "Nordic DFU Service (FE59)",        "risk": "Unauthenticated firmware update possible",           "severity": VulnSeverity.CRITICAL},
    "fddf": {"name": "Mesh Provisioning (FDDF)",         "risk": "Unauthenticated device join",                        "severity": VulnSeverity.HIGH},
    "fe0f": {"name": "Vendor Diagnostic (FE0F)",         "risk": "Debug commands exposed",                            "severity": VulnSeverity.HIGH},
    "fce0": {"name": "Fitbit Service (FCE0)",            "risk": "Proprietary protocol — verify authentication",       "severity": VulnSeverity.MEDIUM},
    # Standard BT SIG services
    "180a": {"name": "Device Information (0x180A)",      "risk": "Device metadata readable without auth",             "severity": VulnSeverity.LOW},
    "180f": {"name": "Battery Service (0x180F)",         "risk": "Battery level disclosure",                          "severity": VulnSeverity.INFO},
    "1812": {"name": "HID (0x1812)",                     "risk": "Keystroke injection if writes are unauthenticated",  "severity": VulnSeverity.HIGH},
    "1826": {"name": "Fitness Machine (0x1826)",         "risk": "Unauthenticated control commands",                  "severity": VulnSeverity.MEDIUM},
    "181c": {"name": "User Data (0x181C)",               "risk": "Personal data exposure (name, age, weight, etc.)",  "severity": VulnSeverity.HIGH},
}

# Characteristics that must NOT be writable without authentication
SENSITIVE_WRITE_CHARS: Dict[str, str] = {
    "2a00": "Device Name",
    "2a06": "Alert Level",
    "2a24": "Model Number",
    "2a25": "Serial Number",
    "2a26": "Firmware Revision",
    "2a27": "Hardware Revision",
    "2a28": "Software Revision",
    "2a29": "Manufacturer Name",
    "2a40": "Ringer Control Point",
    "2a46": "Alert Notification Control Point",
    "2a50": "PnP ID",
    "2a56": "Digital Output",
    "2a57": "Digital Input",
    "2b1e": "Timed Challenge Response",
}

# Characteristics whose readable values constitute an info leak
INFO_LEAK_CHARS: Dict[str, str] = {
    "2a00": "Device Name",
    "2a01": "Appearance",
    "2a23": "System ID",
    "2a24": "Model Number",
    "2a25": "Serial Number",
    "2a26": "Firmware Revision",
    "2a27": "Hardware Revision",
    "2a28": "Software Revision",
    "2a29": "Manufacturer Name",
    "2a50": "PnP ID",
    # Privacy-sensitive user data
    "2a85": "Date of Birth",
    "2a8a": "First Name",
    "2a8c": "Gender",
    "2a90": "Last Name",
}

# Non-destructive test payloads (smallest/safest first)
_TEST_PAYLOADS = [
    bytes([0x00]),
    bytes([0x01]),
    bytes([0x00, 0x00]),
    bytes([0x41, 0x41, 0x41, 0x41]),
]


class Module(ScannerModule):
    """
    BLE Vulnerability Scanner

    Detects:
    - Unauthenticated GATT writes on sensitive characteristics
    - Write-without-response on known-risk services
    - Notify/Indicate subscriptions that leak sensitive data
    - Readable info-disclosure characteristics
    - Known vulnerable services (HID, DFU, Mesh, IoT)
    - Personal/private data exposure
    """

    info = ModuleInfo(
        name="scanners/ble_vuln_scan",
        description="BLE GATT vulnerability scanner — unauth writes, info leaks, sensitive UUIDs",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.HIGH,
        references=[
            "https://www.usenix.org/conference/usenixsecurity19/presentation/wu-jianliang",
            "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/"
        ]
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target",
                required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)"
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Connection timeout in seconds",
                default=15
            ),
            "test_writes": ModuleOption(
                name="test_writes",
                required=False,
                description="Actually test write operations (may modify device state)",
                default=False
            ),
            "deep_scan": ModuleOption(
                name="deep_scan",
                required=False,
                description="Perform deep analysis including info disclosure reads (slower)",
                default=True
            ),
            "output_file": ModuleOption(
                name="output_file",
                required=False,
                description="Save results to JSON file",
                default=None
            )
        }

    def _get_short_uuid(self, uuid: str) -> str:
        return _short_uuid(uuid)

    async def _test_unauth_write(self, client: BleakClient, char_uuid: str) -> bool:
        """Return True if the characteristic accepts a write without prior authentication."""
        for payload in _TEST_PAYLOADS:
            try:
                await client.write_gatt_char(char_uuid, payload, response=False)
                return True
            except BleakError as e:
                err = str(e).lower()
                if any(k in err for k in ("auth", "encrypt", "insufficient", "not permit", "not support")):
                    return False
                # Unknown BleakError — try next payload
            except Exception:
                continue
        return False

    async def _read_char(self, client: BleakClient, char_uuid: str) -> Optional[str]:
        """Read a characteristic and return its value as a printable string, or None."""
        try:
            raw = await client.read_gatt_char(char_uuid)
            if not raw:
                return None
            try:
                decoded = raw.decode("utf-8").strip("\x00").strip()
                return decoded if decoded else raw.hex()
            except Exception:
                return raw.hex()
        except Exception:
            return None

    async def _scan_async(self, address: str) -> ScanResult:
        """Core async scan logic."""
        timeout = int(self.get_option("timeout"))
        test_writes = self.get_option("test_writes")
        deep_scan = self.get_option("deep_scan")

        result = ScanResult(address=address, name="")
        print_info(f"Connecting to {address}...")

        try:
            async with BleakClient(address, timeout=timeout) as client:
                if not client.is_connected:
                    print_error("Failed to connect")
                    return result

                print_success(f"Connected to {address}")

                # Resolve device name
                try:
                    for svc in client.services:
                        for ch in svc.characteristics:
                            if _short_uuid(str(ch.uuid)) == "2a00":
                                raw = await client.read_gatt_char(ch.uuid)
                                result.name = raw.decode("utf-8").strip("\x00")
                                break
                        if result.name:
                            break
                except Exception:
                    pass

                total_chars = sum(len(list(s.characteristics)) for s in client.services)
                print_info(f"Scanning {total_chars} characteristics across {len(list(client.services))} services...\n")

                # Track char UUIDs that already have a write-related finding to avoid duplicates
                seen_write_findings: set = set()

                for service in client.services:
                    svc_uuid = str(service.uuid).lower()
                    short_svc = _short_uuid(svc_uuid)
                    result.services_count += 1

                    # Known vulnerable service
                    if short_svc and short_svc in VULN_PATTERNS:
                        pat = VULN_PATTERNS[short_svc]
                        result.vulns.append(Vulnerability(
                            name=f"Known Risk Service: {pat['name']}",
                            severity=pat["severity"],
                            description=pat["risk"],
                            affected=svc_uuid,
                            details=f"Service {short_svc.upper()} has documented security concerns",
                            recommendation="Verify all characteristics require authentication"
                        ))

                    for char in service.characteristics:
                        char_uuid = str(char.uuid).lower()
                        short_char = _short_uuid(char_uuid)
                        props = set(char.properties)
                        result.chars_count += 1

                        is_writable     = bool(props & {"write", "write-without-response"})
                        is_readable     = "read" in props
                        is_wnr          = "write-without-response" in props
                        has_notify      = bool(props & {"notify", "indicate"})

                        if is_writable:
                            result.writable_count += 1
                        if has_notify:
                            result.notify_count += 1

                        # --- Sensitive characteristic writable (highest priority write check) ---
                        if is_writable and short_char and short_char in SENSITIVE_WRITE_CHARS:
                            char_name = SENSITIVE_WRITE_CHARS[short_char]
                            sev = VulnSeverity.CRITICAL if is_wnr else VulnSeverity.HIGH
                            extra = (
                                " write-without-response means no ACK or implicit auth check."
                                if is_wnr else ""
                            )
                            result.vulns.append(Vulnerability(
                                name=f"Sensitive Char Writable: {char_name}",
                                severity=sev,
                                description=f"{char_name} ({short_char.upper()}) is writable without confirmed authentication",
                                affected=char_uuid,
                                details=f"Properties: {', '.join(sorted(props))}.{extra}",
                                recommendation="Require an encrypted+authenticated link before allowing writes"
                            ))
                            seen_write_findings.add(char_uuid)

                        # --- write-without-response on a known-risk service (deduplicated) ---
                        elif is_wnr and short_svc and short_svc in VULN_PATTERNS:
                            if char_uuid not in seen_write_findings:
                                result.vulns.append(Vulnerability(
                                    name="Write-Without-Response on Risk Service",
                                    severity=VulnSeverity.MEDIUM,
                                    description=(
                                        f"Characteristic in known-risk service {short_svc.upper()} "
                                        f"({VULN_PATTERNS[short_svc]['name']}) allows write-without-response"
                                    ),
                                    affected=char_uuid,
                                    details=f"Properties: {', '.join(sorted(props))}",
                                    recommendation="Verify authentication is enforced server-side for all writes"
                                ))
                                seen_write_findings.add(char_uuid)

                        # --- Notify/Indicate on sensitive char → potential passive data leak ---
                        if has_notify and short_char and short_char in INFO_LEAK_CHARS:
                            result.vulns.append(Vulnerability(
                                name=f"Unencrypted Notify: {INFO_LEAK_CHARS[short_char]}",
                                severity=VulnSeverity.MEDIUM,
                                description=(
                                    f"{INFO_LEAK_CHARS[short_char]} supports notifications — "
                                    f"a nearby attacker can subscribe and receive updates without pairing"
                                ),
                                affected=char_uuid,
                                details=f"Properties: {', '.join(sorted(props))}",
                                recommendation="Enable notifications only on encrypted/authenticated links"
                            ))

                        # --- Info disclosure via readable sensitive char (deep scan only) ---
                        if is_readable and short_char and short_char in INFO_LEAK_CHARS and deep_scan:
                            value = await self._read_char(client, char_uuid)
                            if value:
                                result.info_leak_count += 1
                                result.vulns.append(Vulnerability(
                                    name=f"Info Disclosure: {INFO_LEAK_CHARS[short_char]}",
                                    severity=VulnSeverity.LOW,
                                    description=f"Device exposes {INFO_LEAK_CHARS[short_char]} without authentication",
                                    affected=char_uuid,
                                    details=f"Value: {value[:60]}{'...' if len(value) > 60 else ''}",
                                    recommendation="Restrict reads to bonded peers where the data is sensitive"
                                ))

                        # --- Active write test ---
                        if is_writable and test_writes and char_uuid not in seen_write_findings:
                            label = short_char.upper() if short_char else char_uuid[:8]
                            print_info(f"  Testing write on {label}...")
                            if await self._test_unauth_write(client, char_uuid):
                                result.unauth_write_count += 1
                                result.vulns.append(Vulnerability(
                                    name="Unauthenticated Write Confirmed",
                                    severity=VulnSeverity.CRITICAL,
                                    description="Characteristic accepted a write payload without prior pairing or bonding",
                                    affected=char_uuid,
                                    details=(
                                        f"Write succeeded without authentication. "
                                        f"Service: {short_svc.upper() if short_svc else svc_uuid[:8]}"
                                    ),
                                    recommendation="Implement BLE pairing/bonding and enforce on every write",
                                    cve="Pre-pairing GATT — no specific CVE"
                                ))

                # --- All writable chars lack auth (only meaningful when test_writes ran) ---
                if (test_writes and result.writable_count > 0
                        and result.unauth_write_count == result.writable_count):
                    result.vulns.append(Vulnerability(
                        name="No Write Authentication Anywhere",
                        severity=VulnSeverity.CRITICAL,
                        description="Every writable characteristic accepted an unauthenticated write",
                        affected="All writable characteristics",
                        details=f"All {result.writable_count} writable chars lack auth enforcement",
                        recommendation="Implement BLE pairing/bonding requirements globally"
                    ))

                # --- Large attack surface hint (only when not actively tested) ---
                if not test_writes and result.writable_count > 8:
                    result.vulns.append(Vulnerability(
                        name="Large Writable Attack Surface",
                        severity=VulnSeverity.MEDIUM,
                        description=f"Device exposes {result.writable_count} writable characteristics",
                        affected="Multiple",
                        details="High writable characteristic count increases unauthenticated write risk",
                        recommendation="Run with test_writes=true to verify each requires authentication"
                    ))

                print_success("Vulnerability scan complete")

        except asyncio.TimeoutError:
            print_error(f"Connection timed out after {timeout}s")
        except BleakError as e:
            print_error(f"BLE error: {e}")
        except Exception as e:
            print_error(f"Scan error: {e}")

        return result

    def _print_results(self, result: ScanResult) -> None:
        C = Colors

        sev_colors = {
            VulnSeverity.CRITICAL: C.RED + C.BOLD,
            VulnSeverity.HIGH:     C.RED,
            VulnSeverity.MEDIUM:   C.YELLOW,
            VulnSeverity.LOW:      C.GREEN,
            VulnSeverity.INFO:     C.CYAN,
        }

        print(f"\n  {C.CYAN}{'='*100}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}BLE VULNERABILITY SCAN RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*100}{C.RESET}")
        print(f"  Target: {C.WHITE}{result.address}{C.RESET}")
        print(f"  Name  : {C.WHITE}{result.name or 'Unknown'}{C.RESET}\n")

        print(f"  {C.BOLD}SCAN STATISTICS{C.RESET}\n")
        print(f"  {C.DARK_GREY}+------------------------------+----------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {'Metric':<28} {C.DARK_GREY}|{C.RESET} {'Value':<8} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+------------------------------+----------+{C.RESET}")
        stats = [
            ("Services",                  str(result.services_count),     C.RESET),
            ("Characteristics",           str(result.chars_count),         C.RESET),
            ("Writable Chars",            str(result.writable_count),      C.YELLOW),
            ("Notify/Indicate Chars",     str(result.notify_count),        C.RESET),
            ("Confirmed Unauth Writes",   str(result.unauth_write_count),  C.RED if result.unauth_write_count else C.RESET),
            ("Info Disclosures",          str(result.info_leak_count),     C.RESET),
            ("Total Vulnerabilities",     str(len(result.vulns)),          C.RED if result.vulns else C.GREEN),
        ]
        for label, val, color in stats:
            print(f"  {C.DARK_GREY}|{C.RESET} {label:<28} {C.DARK_GREY}|{C.RESET} {color}{val:<8}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+------------------------------+----------+{C.RESET}")

        if not result.vulns:
            print(f"\n  {C.GREEN}[+] No vulnerabilities detected{C.RESET}")
            print(f"\n  {C.CYAN}{'='*100}{C.RESET}\n")
            return

        sev_counts = {s: 0 for s in VulnSeverity}
        for v in result.vulns:
            sev_counts[v.severity] += 1

        print(f"\n  {C.BOLD}VULNERABILITY SUMMARY{C.RESET}")
        print(
            f"  {C.RED + C.BOLD}CRITICAL: {sev_counts[VulnSeverity.CRITICAL]}{C.RESET}  "
            f"{C.RED}HIGH: {sev_counts[VulnSeverity.HIGH]}{C.RESET}  "
            f"{C.YELLOW}MEDIUM: {sev_counts[VulnSeverity.MEDIUM]}{C.RESET}  "
            f"{C.GREEN}LOW: {sev_counts[VulnSeverity.LOW]}{C.RESET}  "
            f"{C.CYAN}INFO: {sev_counts[VulnSeverity.INFO]}{C.RESET}"
        )

        sev_order = {
            VulnSeverity.CRITICAL: 0, VulnSeverity.HIGH: 1,
            VulnSeverity.MEDIUM: 2,   VulnSeverity.LOW: 3, VulnSeverity.INFO: 4
        }
        sorted_vulns = sorted(result.vulns, key=lambda v: sev_order[v.severity])

        print(f"\n  {C.BOLD}VULNERABILITIES FOUND ({len(result.vulns)}){C.RESET}\n")
        print(f"  {C.DARK_GREY}+-----+----------+------------------------------------------+----------------------------------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {C.BOLD}{'#':<3}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'SEVERITY':<8}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'VULNERABILITY':<40}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'AFFECTED':<32}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+-----+----------+------------------------------------------+----------------------------------+{C.RESET}")

        for idx, vuln in enumerate(sorted_vulns, 1):
            name     = (vuln.name[:38]     + "..") if len(vuln.name)     > 40 else vuln.name
            affected = (vuln.affected[:30] + "..") if len(vuln.affected) > 32 else vuln.affected
            sc = sev_colors[vuln.severity]
            print(f"  {C.DARK_GREY}|{C.RESET} {idx:<3} {C.DARK_GREY}|{C.RESET} {sc}{vuln.severity.value:<8}{C.RESET} {C.DARK_GREY}|{C.RESET} {name:<40} {C.DARK_GREY}|{C.RESET} {affected:<32} {C.DARK_GREY}|{C.RESET}")

        print(f"  {C.DARK_GREY}+-----+----------+------------------------------------------+----------------------------------+{C.RESET}")

        print(f"\n  {C.BOLD}VULNERABILITY DETAILS{C.RESET}\n")
        for idx, vuln in enumerate(sorted_vulns, 1):
            sc = sev_colors[vuln.severity]
            print(f"  {sc}[{idx}] {vuln.name}{C.RESET}")
            print(f"  {C.DARK_GREY}{'─'*90}{C.RESET}")
            print(f"      Severity       : {sc}{vuln.severity.value}{C.RESET}")
            print(f"      Affected       : {vuln.affected}")
            print(f"      Description    : {vuln.description}")
            print(f"      Details        : {vuln.details}")
            print(f"      Recommendation : {vuln.recommendation}")
            if vuln.cve:
                print(f"      CVE            : {vuln.cve}")
            print()

        print(f"  {C.CYAN}{'-'*100}{C.RESET}")
        print(f"  {C.BOLD}RISK ASSESSMENT{C.RESET}")
        print(f"  {C.CYAN}{'-'*100}{C.RESET}")
        if sev_counts[VulnSeverity.CRITICAL] > 0:
            print(f"  {C.RED}[!] CRITICAL RISK: Device has critical vulnerabilities requiring immediate attention{C.RESET}")
        elif sev_counts[VulnSeverity.HIGH] > 0:
            print(f"  {C.RED}[!] HIGH RISK: Device has high severity vulnerabilities{C.RESET}")
        elif sev_counts[VulnSeverity.MEDIUM] > 0:
            print(f"  {C.YELLOW}[!] MODERATE RISK: Device has medium severity issues{C.RESET}")
        else:
            print(f"  {C.GREEN}[+] LOW RISK: Only low severity or informational findings{C.RESET}")

        if result.unauth_write_count > 0:
            print(f"\n  {C.YELLOW}NEXT STEPS:{C.RESET}")
            print(f"    1. Test unauth writes with exploits/ble/unauth_write module")
            print(f"    2. Capture traffic to analyze the protocol")
            print(f"    3. Check for replay attack possibilities")

        print(f"\n  {C.CYAN}{'='*100}{C.RESET}\n")

    def _save_results(self, result: ScanResult, filename: str) -> None:
        output = {
            "target": result.address,
            "name": result.name,
            "statistics": {
                "services":         result.services_count,
                "characteristics":  result.chars_count,
                "writable":         result.writable_count,
                "notify_indicate":  result.notify_count,
                "unauth_writes":    result.unauth_write_count,
                "info_leaks":       result.info_leak_count,
                "total_vulns":      len(result.vulns),
            },
            "vulnerabilities": [
                {
                    "name":           v.name,
                    "severity":       v.severity.value,
                    "description":    v.description,
                    "affected":       v.affected,
                    "details":        v.details,
                    "recommendation": v.recommendation,
                    "cve":            v.cve,
                }
                for v in result.vulns
            ],
        }
        try:
            with open(filename, "w") as f:
                json.dump(output, f, indent=2)
            print_success(f"Saved: {filename}")
        except Exception as e:
            print_error(f"Save failed: {e}")

    def run(self) -> bool:
        if not BLEAK_AVAILABLE:
            print_error("Install bleak: pip install bleak")
            return False

        target = self.target
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        test_writes = self.get_option("test_writes")
        if test_writes:
            print_warning("test_writes enabled — this may modify device state!")
            print_info("Proceeding in 3 seconds... (Ctrl+C to cancel)")
            try:
                import time
                time.sleep(3)
            except KeyboardInterrupt:
                print_warning("Cancelled")
                return False

        try:
            try:
                result = asyncio.run(self._scan_async(target))
            except RuntimeError as e:
                # Already inside a running event loop (e.g. some interactive environments)
                if "running event loop" not in str(e):
                    raise
                loop = asyncio.get_event_loop()
                result = loop.run_until_complete(self._scan_async(target))

            self.add_result(result)
            self._print_results(result)

            out = self.get_option("output_file")
            if out:
                self._save_results(result, out)

            return len(result.vulns) > 0 or result.services_count > 0

        except KeyboardInterrupt:
            print_warning("\nInterrupted")
            return False
        except Exception as e:
            print_error(f"Scan failed: {e}")
            return False
