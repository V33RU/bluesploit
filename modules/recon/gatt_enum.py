"""
BlueSploit Module: GATT Enumerator (deprecated wrapper)

All functionality has been merged into `recon/ble_target_enum`, which
now includes the device identity header, chipset detection, PnP ID
decode, and writable/notify attack-surface summary that this module
previously provided.

Use `recon/ble_target_enum` going forward. This wrapper exists only
for backwards compatibility and will be removed in a future version.
"""

from core.base import BTProtocol, ModuleInfo, ModuleOption, ReconModule, Severity
from core.utils.printer import print_warning


class Module(ReconModule):

    info = ModuleInfo(
        name="GATT Enumerator (use recon/ble_target_enum)",
        description="Enumerate GATT services and characteristics + device identity (deprecated - use recon/ble_target_enum which now includes all features)",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/gatt/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BLE BD_ADDR",
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter (Linux only, e.g. hci0)",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="Connection timeout in seconds",
            default=15,
        ))
        self.add_option(ModuleOption(
            name="read_values",
            required=False,
            description="Read characteristic values (true/false)",
            default=True,
        ))

    def run(self) -> bool:
        print_warning(
            "recon/gatt_enum is deprecated. Use `recon/ble_target_enum` instead, "
            "which includes all gatt_enum features plus descriptor reads and "
            "store fingerprint persistence."
        )

        from core.loader import ModuleLoader
        loader = ModuleLoader()
        mod = loader.load("recon/ble_target_enum")
        if mod is None:
            from core.utils.printer import print_error
            print_error("Could not load recon/ble_target_enum")
            return False

        mod.set_option("target",       self.get_option("target"))
        mod.set_option("interface",    self.get_option("interface") or "hci0")
        mod.set_option("timeout",      self.get_option("timeout") or 15)
        mod.set_option("read_values",  self.get_option("read_values"))
        return mod.run()
