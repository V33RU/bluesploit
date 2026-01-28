"""
BlueSploit Base Module Classes
Defines the foundation for all exploit, scanner, and auxiliary modules
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import re


class ModuleType(Enum):
    """Types of modules supported by BlueSploit"""
    EXPLOIT = "exploits"
    SCANNER = "scanners"
    CREDS = "creds"
    AUXILIARY = "auxiliary"
    PAYLOAD = "payloads"


class BTProtocol(Enum):
    """Bluetooth protocol types"""
    CLASSIC = "classic"      # BR/EDR
    BLE = "ble"              # Bluetooth Low Energy
    DUAL = "dual"            # Both supported


class Severity(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ModuleOption:
    """
    Represents a configurable option for a module
    """
    name: str
    required: bool
    description: str
    default: Any = None
    current: Any = None
    
    def __post_init__(self):
        if self.current is None and self.default is not None:
            self.current = self.default
    
    @property
    def value(self) -> Any:
        return self.current if self.current is not None else self.default
    
    @property
    def is_set(self) -> bool:
        return self.current is not None or self.default is not None


@dataclass
class ModuleInfo:
    """
    Metadata about a module
    """
    name: str
    description: str
    author: List[str]
    protocol: BTProtocol = BTProtocol.BLE
    references: List[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    cve: Optional[str] = None
    
    def __str__(self) -> str:
        return f"{self.name} - {self.description}"


@dataclass
class Target:
    """
    Represents a Bluetooth target device
    """
    address: str
    name: Optional[str] = None
    rssi: Optional[int] = None
    manufacturer: Optional[str] = None
    device_type: Optional[str] = None
    services: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        name_str = self.name or "Unknown"
        return f"{self.address} ({name_str})"


@dataclass
class ScanResult:
    """
    Result from a scanner module
    """
    target: Target
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    characteristics: List[Dict[str, Any]] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExploitResult:
    """
    Result from an exploit module
    """
    success: bool
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    shell: Optional[Any] = None  # For reverse shell connections


class BaseModule(ABC):
    """
    Abstract base class for all BlueSploit modules
    
    All modules must inherit from this class and implement:
    - _setup_options(): Define module-specific options
    - run(): Execute the module's main functionality
    """
    
    module_type: ModuleType
    info: ModuleInfo
    
    def __init__(self):
        self.options: Dict[str, ModuleOption] = {}
        self._results: List[Any] = []
        self._setup_options()
    
    @abstractmethod
    def _setup_options(self) -> None:
        """
        Define module-specific options
        Must be implemented by subclasses
        """
        pass
    
    @abstractmethod
    def run(self) -> bool:
        """
        Execute the module
        Must be implemented by subclasses
        Returns True on success, False on failure
        """
        pass
    
    def set_option(self, name: str, value: Any) -> bool:
        """
        Set a module option value
        
        Args:
            name: Option name
            value: Value to set
            
        Returns:
            True if option was set, False if option doesn't exist
        """
        name_lower = name.lower()
        for opt_name, opt in self.options.items():
            if opt_name.lower() == name_lower:
                # Type conversion based on default value type
                if opt.default is not None:
                    try:
                        if isinstance(opt.default, bool):
                            value = value.lower() in ('true', '1', 'yes')
                        elif isinstance(opt.default, int):
                            value = int(value)
                        elif isinstance(opt.default, float):
                            value = float(value)
                    except (ValueError, AttributeError):
                        pass
                opt.current = value
                return True
        return False
    
    def get_option(self, name: str) -> Any:
        """Get the current value of an option"""
        name_lower = name.lower()
        for opt_name, opt in self.options.items():
            if opt_name.lower() == name_lower:
                return opt.value
        return None
    
    def validate_options(self) -> bool:
        """
        Validate that all required options are set
        
        Returns:
            True if all required options are set, False otherwise
        """
        for name, opt in self.options.items():
            if opt.required and not opt.is_set:
                print(f"[\033[91m!\033[0m] Required option not set: {name}")
                return False
        return True
    
    def validate_bd_addr(self, address: str) -> bool:
        """
        Validate Bluetooth device address format
        
        Args:
            address: BD_ADDR to validate (XX:XX:XX:XX:XX:XX format)
            
        Returns:
            True if valid, False otherwise
        """
        pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
        return bool(re.match(pattern, address))
    
    @property
    def target(self) -> Optional[str]:
        """Convenience property to get target address"""
        return self.get_option("target")
    
    @property
    def results(self) -> List[Any]:
        """Get stored results"""
        return self._results
    
    def add_result(self, result: Any) -> None:
        """Store a result"""
        self._results.append(result)
    
    def clear_results(self) -> None:
        """Clear stored results"""
        self._results.clear()
    
    def show_options(self) -> None:
        """Display all module options in a formatted table"""
        print(f"\n  Module: {self.info.name}")
        print(f"  {self.info.description}\n")
        print("  Options:")
        print("  " + "=" * 70)
        print(f"  {'Name':<15} {'Current':<20} {'Required':<10} {'Description'}")
        print("  " + "-" * 70)
        
        for name, opt in self.options.items():
            current = str(opt.value) if opt.value is not None else ""
            required = "Yes" if opt.required else "No"
            print(f"  {name:<15} {current:<20} {required:<10} {opt.description}")
        
        print("  " + "=" * 70 + "\n")
    
    def show_info(self) -> None:
        """Display detailed module information"""
        print(f"\n  Name: {self.info.name}")
        print(f"  Description: {self.info.description}")
        print(f"  Author(s): {', '.join(self.info.author)}")
        print(f"  Protocol: {self.info.protocol.value}")
        print(f"  Severity: {self.info.severity.value}")
        
        if self.info.cve:
            print(f"  CVE: {self.info.cve}")
        
        if self.info.references:
            print("  References:")
            for ref in self.info.references:
                print(f"    - {ref}")
        print()


class ScannerModule(BaseModule):
    """Base class for scanner modules"""
    module_type = ModuleType.SCANNER
    
    def __init__(self):
        super().__init__()
        self.discovered_devices: List[Target] = []
    
    def add_device(self, device: Target) -> None:
        """Add a discovered device"""
        self.discovered_devices.append(device)
    
    def clear_devices(self) -> None:
        """Clear discovered devices"""
        self.discovered_devices.clear()


class ExploitModule(BaseModule):
    """Base class for exploit modules"""
    module_type = ModuleType.EXPLOIT
    
    def check(self) -> bool:
        """
        Check if target is vulnerable without exploiting
        Override in subclass for exploit-specific checks
        """
        print("[\033[93m*\033[0m] Check not implemented for this module")
        return False


class CredsModule(BaseModule):
    """Base class for credential testing modules"""
    module_type = ModuleType.CREDS
    
    def __init__(self):
        super().__init__()
        self.valid_creds: List[Dict[str, str]] = []
    
    def add_valid_cred(self, cred: Dict[str, str]) -> None:
        """Store a valid credential"""
        self.valid_creds.append(cred)


class AuxiliaryModule(BaseModule):
    """Base class for auxiliary modules"""
    module_type = ModuleType.AUXILIARY


class PayloadModule(BaseModule):
    """Base class for payload modules"""
    module_type = ModuleType.PAYLOAD
    
    @abstractmethod
    def generate(self) -> bytes:
        """Generate the payload bytes"""
        pass
