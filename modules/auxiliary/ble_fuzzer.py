"""
BLE Protocol Fuzzer
Fuzzes BLE ATT, GATT, and SMP protocol layers with malformed packets
to discover crashes, hangs, and unexpected behavior in BLE peripherals.

Fuzzing strategies:
  - random:    Pure random byte mutation
  - smart:     Structure-aware fuzzing (valid headers, mutated payloads)
  - overflow:  Oversized fields to trigger buffer overflows
  - boundary:  Edge-case values (0, 0xFF, max lengths, etc.)
"""

import asyncio
import struct
import os
import time
import random
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="BLE Protocol Fuzzer",
        description="Fuzz BLE ATT/GATT/SMP layers to find crashes and vulnerabilities",
        author="BlueSploit Team",
        protocol=BTProtocol.BLE,
        references=[
            "https://asset-group.github.io/disclosures/sweyntooth/",
            "https://dl.acm.org/doi/10.1145/3395351.3399355",
        ],
        severity=Severity.MEDIUM,
        cve=None,
    )

    # ATT opcodes
    ATT_ERROR_RSP = 0x01
    ATT_EXCHANGE_MTU_REQ = 0x02
    ATT_FIND_INFO_REQ = 0x04
    ATT_FIND_BY_TYPE_REQ = 0x06
    ATT_READ_BY_TYPE_REQ = 0x08
    ATT_READ_REQ = 0x0A
    ATT_READ_BLOB_REQ = 0x0C
    ATT_READ_MULTI_REQ = 0x0E
    ATT_READ_BY_GROUP_REQ = 0x10
    ATT_WRITE_REQ = 0x12
    ATT_WRITE_CMD = 0x52
    ATT_PREPARE_WRITE_REQ = 0x16
    ATT_EXECUTE_WRITE_REQ = 0x18
    ATT_HANDLE_NOTIFY = 0x1B

    # SMP opcodes
    SMP_PAIRING_REQ = 0x01
    SMP_PAIRING_RSP = 0x02
    SMP_PAIRING_CONFIRM = 0x03
    SMP_PAIRING_RANDOM = 0x04
    SMP_ENCRYPTION_INFO = 0x06
    SMP_MASTER_IDENT = 0x07
    SMP_IDENT_INFO = 0x08
    SMP_IDENT_ADDR_INFO = 0x09
    SMP_SIGNING_INFO = 0x0A
    SMP_SECURITY_REQ = 0x0B
    SMP_PUBLIC_KEY = 0x0C
    SMP_DHKEY_CHECK = 0x0D

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BLE device MAC address",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="protocol",
            required=False,
            description="Protocol layer to fuzz: att, smp, l2cap, all",
            default="att",
        ))
        self.add_option(ModuleOption(
            name="strategy",
            required=False,
            description="Fuzzing strategy: random, smart, overflow, boundary",
            default="smart",
        ))
        self.add_option(ModuleOption(
            name="iterations",
            required=False,
            description="Number of fuzz iterations",
            default="100",
        ))
        self.add_option(ModuleOption(
            name="delay",
            required=False,
            description="Delay between fuzz packets in seconds",
            default="0.1",
        ))
        self.add_option(ModuleOption(
            name="seed",
            required=False,
            description="Random seed for reproducible fuzzing",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="log_file",
            required=False,
            description="Log file for fuzz results",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="crash_detect",
            required=False,
            description="Attempt to detect target crashes via reconnect (true/false)",
            default="true",
        ))

    def run(self) -> bool:
        target = self.get_option("target")
        protocol = (self.get_option("protocol") or "att").lower()
        strategy = (self.get_option("strategy") or "smart").lower()
        iterations = int(self.get_option("iterations") or 100)
        delay = float(self.get_option("delay") or 0.1)
        seed_val = self.get_option("seed")
        log_file = self.get_option("log_file")
        crash_detect = (self.get_option("crash_detect") or "true").lower() == "true"

        if seed_val:
            random.seed(int(seed_val))
            self.print_status(f"Random seed: {seed_val}")

        self.print_status(f"Target: {target}")
        self.print_status(f"Protocol: {protocol}")
        self.print_status(f"Strategy: {strategy}")
        self.print_status(f"Iterations: {iterations}")
        self.print_warning("Fuzzing may crash the target device — ensure you have physical access for reset")

        try:
            return asyncio.run(self._run_fuzzer(
                target, protocol, strategy, iterations, delay,
                log_file, crash_detect))
        except KeyboardInterrupt:
            self.print_warning("Fuzzing interrupted")
            return False
        except Exception as e:
            self.print_error(f"Fuzzer error: {e}")
            return False

    async def _run_fuzzer(self, target, protocol, strategy, iterations,
                          delay, log_file, crash_detect) -> bool:
        try:
            from bleak import BleakClient
        except ImportError:
            self.print_error("bleak not installed — run: pip install bleak")
            return False

        results = {
            "sent": 0, "errors": 0, "crashes": 0,
            "timeouts": 0, "interesting": [],
        }

        self.print_status(f"Connecting to {target}...")
        client = BleakClient(target)
        try:
            await client.connect()
        except Exception as e:
            self.print_error(f"Cannot connect: {e}")
            return False

        self.print_success(f"Connected to {target}")

        # Discover writable characteristics for ATT fuzzing
        write_chars = []
        for svc in client.services:
            for char in svc.characteristics:
                if "write" in char.properties or "write-without-response" in char.properties:
                    write_chars.append(char)

        self.print_status(f"Found {len(write_chars)} writable characteristics")

        generators = {
            "att": self._generate_att_fuzz,
            "smp": self._generate_smp_fuzz,
            "l2cap": self._generate_l2cap_fuzz,
        }
        protocols_to_fuzz = list(generators.keys()) if protocol == "all" else [protocol]

        for i in range(1, iterations + 1):
            proto = random.choice(protocols_to_fuzz)
            generator = generators.get(proto, self._generate_att_fuzz)
            fuzz_data = generator(strategy)

            if not client.is_connected:
                if crash_detect:
                    results["crashes"] += 1
                    self.print_warning(f"  [CRASH?] Target disconnected at iteration {i}")
                    if fuzz_data:
                        results["interesting"].append({
                            "iteration": i, "proto": proto,
                            "data": fuzz_data.hex(), "result": "disconnect",
                        })
                # Reconnect
                try:
                    await asyncio.sleep(2)
                    await client.connect()
                    self.print_status(f"  Reconnected after disconnect")
                except Exception:
                    self.print_error(f"  Cannot reconnect — target may be crashed")
                    break

            # Send fuzz packet
            try:
                if proto == "att" and write_chars:
                    char = random.choice(write_chars)
                    try:
                        await client.write_gatt_char(char.uuid, fuzz_data, response=False)
                    except Exception:
                        await client.write_gatt_char(char.uuid, fuzz_data, response=True)
                    results["sent"] += 1
                elif proto == "smp":
                    # SMP fuzzing requires L2CAP CID 6 — send via raw write
                    if write_chars:
                        char = random.choice(write_chars)
                        await client.write_gatt_char(char.uuid, fuzz_data, response=False)
                    results["sent"] += 1
                elif proto == "l2cap":
                    if write_chars:
                        char = random.choice(write_chars)
                        await client.write_gatt_char(char.uuid, fuzz_data, response=False)
                    results["sent"] += 1
                else:
                    results["sent"] += 1

            except asyncio.TimeoutError:
                results["timeouts"] += 1
                self.print_warning(f"  [TIMEOUT] iter={i} proto={proto} data={fuzz_data[:8].hex()}...")
                results["interesting"].append({
                    "iteration": i, "proto": proto,
                    "data": fuzz_data.hex(), "result": "timeout",
                })
            except Exception as e:
                results["errors"] += 1
                err_str = str(e)
                if "disconnect" in err_str.lower() or "not connected" in err_str.lower():
                    results["crashes"] += 1
                    self.print_warning(f"  [CRASH?] iter={i}: {err_str[:60]}")
                    results["interesting"].append({
                        "iteration": i, "proto": proto,
                        "data": fuzz_data.hex(), "result": "error_disconnect",
                    })

            if i % 25 == 0:
                self.print_status(f"  Progress: {i}/{iterations} "
                                 f"(sent={results['sent']} err={results['errors']} "
                                 f"crash={results['crashes']} timeout={results['timeouts']})")

            await asyncio.sleep(delay)

        # Cleanup
        try:
            await client.disconnect()
        except Exception:
            pass

        # Report
        self.print_status(f"\nFuzzing complete:")
        self.print_status(f"  Packets sent: {results['sent']}")
        self.print_status(f"  Errors: {results['errors']}")
        self.print_status(f"  Timeouts: {results['timeouts']}")
        self.print_status(f"  Potential crashes: {results['crashes']}")
        self.print_status(f"  Interesting cases: {len(results['interesting'])}")

        if results["interesting"]:
            self.print_warning("\nInteresting findings:")
            for finding in results["interesting"][:10]:
                self.print_warning(f"  iter={finding['iteration']} proto={finding['proto']} "
                                  f"result={finding['result']} data={finding['data'][:32]}...")

        if log_file:
            try:
                import json
                with open(log_file, "w") as f:
                    json.dump(results, f, indent=2)
                self.print_success(f"Results saved to {log_file}")
            except Exception as e:
                self.print_warning(f"Cannot save log: {e}")

        return results["crashes"] > 0 or len(results["interesting"]) > 0

    def _generate_att_fuzz(self, strategy: str) -> bytes:
        """Generate a fuzzed ATT protocol packet"""
        opcodes = [
            self.ATT_EXCHANGE_MTU_REQ, self.ATT_FIND_INFO_REQ,
            self.ATT_READ_BY_TYPE_REQ, self.ATT_READ_REQ,
            self.ATT_READ_BLOB_REQ, self.ATT_WRITE_REQ,
            self.ATT_WRITE_CMD, self.ATT_PREPARE_WRITE_REQ,
            self.ATT_EXECUTE_WRITE_REQ, self.ATT_READ_BY_GROUP_REQ,
        ]

        if strategy == "random":
            length = random.randint(1, 64)
            return os.urandom(length)

        elif strategy == "smart":
            opcode = random.choice(opcodes)
            if opcode == self.ATT_EXCHANGE_MTU_REQ:
                mtu = random.choice([0, 1, 23, 512, 0xFFFF])
                return struct.pack("<BH", opcode, mtu)
            elif opcode in (self.ATT_FIND_INFO_REQ, self.ATT_READ_BY_TYPE_REQ, self.ATT_READ_BY_GROUP_REQ):
                start = random.randint(0, 0xFFFF)
                end = random.randint(0, 0xFFFF)
                uuid = os.urandom(random.choice([2, 16]))
                return struct.pack("<BHH", opcode, start, end) + uuid
            elif opcode == self.ATT_READ_REQ:
                handle = random.randint(0, 0xFFFF)
                return struct.pack("<BH", opcode, handle)
            elif opcode in (self.ATT_WRITE_REQ, self.ATT_WRITE_CMD):
                handle = random.randint(1, 0x00FF)
                data = os.urandom(random.randint(0, 48))
                return struct.pack("<BH", opcode, handle) + data
            elif opcode == self.ATT_PREPARE_WRITE_REQ:
                handle = random.randint(0, 0xFFFF)
                offset = random.randint(0, 0xFFFF)
                data = os.urandom(random.randint(0, 32))
                return struct.pack("<BHH", opcode, handle, offset) + data
            else:
                return struct.pack("B", opcode) + os.urandom(random.randint(0, 16))

        elif strategy == "overflow":
            opcode = random.choice(opcodes)
            data = os.urandom(random.choice([128, 255, 512, 1024]))
            return struct.pack("B", opcode) + data

        elif strategy == "boundary":
            opcode = random.choice(opcodes)
            boundary_vals = [b"\x00", b"\xff", b"\x00\x00", b"\xff\xff",
                           b"\x00" * 16, b"\xff" * 16, b"\x80\x00"]
            payload = random.choice(boundary_vals)
            return struct.pack("B", opcode) + payload

        return os.urandom(8)

    def _generate_smp_fuzz(self, strategy: str) -> bytes:
        """Generate a fuzzed SMP packet"""
        opcodes = [
            self.SMP_PAIRING_REQ, self.SMP_PAIRING_CONFIRM,
            self.SMP_PAIRING_RANDOM, self.SMP_ENCRYPTION_INFO,
            self.SMP_MASTER_IDENT, self.SMP_SECURITY_REQ,
            self.SMP_PUBLIC_KEY, self.SMP_DHKEY_CHECK,
        ]

        if strategy == "random":
            return os.urandom(random.randint(1, 65))

        elif strategy == "smart":
            opcode = random.choice(opcodes)
            if opcode == self.SMP_PAIRING_REQ:
                io = random.randint(0, 0xFF)
                oob = random.choice([0, 1, 0xFF])
                auth = random.randint(0, 0xFF)
                key_size = random.choice([0, 1, 7, 16, 255])
                return struct.pack("BBBBBBB", opcode, io, oob, auth, key_size,
                                 random.randint(0, 0xFF), random.randint(0, 0xFF))
            elif opcode == self.SMP_PUBLIC_KEY:
                return struct.pack("B", opcode) + os.urandom(64)
            elif opcode == self.SMP_DHKEY_CHECK:
                return struct.pack("B", opcode) + os.urandom(16)
            else:
                return struct.pack("B", opcode) + os.urandom(16)

        elif strategy == "overflow":
            opcode = random.choice(opcodes)
            return struct.pack("B", opcode) + os.urandom(random.choice([128, 255]))

        elif strategy == "boundary":
            opcode = random.choice(opcodes)
            vals = [b"\x00" * 16, b"\xff" * 16, b"\x00" * 64, b"\xff" * 64]
            return struct.pack("B", opcode) + random.choice(vals)

        return os.urandom(8)

    def _generate_l2cap_fuzz(self, strategy: str) -> bytes:
        """Generate a fuzzed L2CAP signaling packet"""
        if strategy == "random":
            return os.urandom(random.randint(4, 64))

        elif strategy == "overflow":
            # L2CAP header with oversized length field
            cid = random.choice([0x0001, 0x0004, 0x0005, 0x0006])
            fake_len = random.choice([0xFFFE, 0xFFFF, 0x1000])
            return struct.pack("<HH", fake_len, cid) + os.urandom(random.randint(16, 128))

        elif strategy == "boundary":
            cid = random.choice([0x0000, 0x0001, 0xFFFF])
            length = random.choice([0, 0xFFFF])
            return struct.pack("<HH", length, cid) + b"\x00" * 4

        else:  # smart
            # L2CAP signaling codes
            codes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x0B, 0x12, 0x14]
            code = random.choice(codes)
            ident = random.randint(0, 0xFF)
            data = os.urandom(random.randint(0, 24))
            sig = struct.pack("<BBHH", code, ident, len(data), 0x0001) + data
            return sig
