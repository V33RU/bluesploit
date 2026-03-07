"""
BlueSploit UI: TUI Dashboard
Terminal User Interface Dashboard using curses

Author: v33ru
"""

import curses
import time
import threading
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum


class PanelType(Enum):
    """Dashboard panel types"""
    DEVICES = "devices"
    MODULES = "modules"
    OUTPUT = "output"
    STATUS = "status"
    HELP = "help"


@dataclass
class Device:
    """Discovered device"""
    address: str
    name: str
    rssi: int
    device_type: str
    services: List[str]
    last_seen: float


@dataclass
class ModuleInfo:
    """Module information"""
    name: str
    category: str
    description: str


class Panel:
    """Base panel class for dashboard"""
    
    def __init__(self, window, title: str = ""):
        self.window = window
        self.title = title
        self.scroll_pos = 0
        self.selected = 0
        self.items: List[Any] = []
        self.focused = False
    
    def draw_border(self) -> None:
        """Draw panel border with title"""
        h, w = self.window.getmaxyx()
        
        # Border color
        if self.focused:
            self.window.attron(curses.color_pair(2))
        else:
            self.window.attron(curses.color_pair(1))
        
        self.window.border()
        
        # Title
        if self.title:
            title_str = f" {self.title} "
            x = (w - len(title_str)) // 2
            self.window.addstr(0, x, title_str)
        
        if self.focused:
            self.window.attroff(curses.color_pair(2))
        else:
            self.window.attroff(curses.color_pair(1))
    
    def scroll_up(self) -> None:
        """Scroll up"""
        if self.selected > 0:
            self.selected -= 1
            if self.selected < self.scroll_pos:
                self.scroll_pos = self.selected
    
    def scroll_down(self) -> None:
        """Scroll down"""
        if self.selected < len(self.items) - 1:
            self.selected += 1
            h, _ = self.window.getmaxyx()
            visible = h - 2
            if self.selected >= self.scroll_pos + visible:
                self.scroll_pos = self.selected - visible + 1
    
    def draw(self) -> None:
        """Draw panel content - override in subclasses"""
        self.window.clear()
        self.draw_border()
        self.window.refresh()


class DevicesPanel(Panel):
    """Panel showing discovered devices"""
    
    def __init__(self, window):
        super().__init__(window, "Devices")
        self.devices: List[Device] = []
    
    def add_device(self, device: Device) -> None:
        """Add or update device"""
        # Update existing or add new
        for i, d in enumerate(self.devices):
            if d.address == device.address:
                self.devices[i] = device
                return
        self.devices.append(device)
        self.items = self.devices
    
    def draw(self) -> None:
        """Draw devices list"""
        self.window.clear()
        self.draw_border()
        
        h, w = self.window.getmaxyx()
        
        if not self.devices:
            self.window.addstr(h // 2, 2, "No devices found", curses.A_DIM)
        else:
            # Header
            header = f"{'ADDRESS':<18} {'NAME':<15} {'RSSI':<6} {'TYPE'}"
            self.window.attron(curses.A_BOLD)
            self.window.addstr(1, 2, header[:w-4])
            self.window.attroff(curses.A_BOLD)
            
            # Devices
            visible_start = self.scroll_pos
            visible_end = min(visible_start + h - 3, len(self.devices))
            
            for i, device in enumerate(self.devices[visible_start:visible_end]):
                y = i + 2
                idx = visible_start + i
                
                # RSSI color
                if device.rssi >= -50:
                    rssi_color = curses.color_pair(3)  # Green
                elif device.rssi >= -70:
                    rssi_color = curses.color_pair(4)  # Yellow
                else:
                    rssi_color = curses.color_pair(5)  # Red
                
                # Selection highlight
                if idx == self.selected and self.focused:
                    self.window.attron(curses.A_REVERSE)
                
                line = f"{device.address:<18} {device.name[:14]:<15} "
                self.window.addstr(y, 2, line[:w-4])
                
                # RSSI with color
                self.window.attron(rssi_color)
                self.window.addstr(f"{device.rssi:>4}")
                self.window.attroff(rssi_color)
                
                self.window.addstr(f"  {device.device_type[:10]}")
                
                if idx == self.selected and self.focused:
                    self.window.attroff(curses.A_REVERSE)
        
        self.window.refresh()


class ModulesPanel(Panel):
    """Panel showing available modules"""
    
    def __init__(self, window):
        super().__init__(window, "Modules")
        self.modules: List[ModuleInfo] = []
        self.filter_category: Optional[str] = None
    
    def set_modules(self, modules: List[ModuleInfo]) -> None:
        """Set modules list"""
        self.modules = modules
        self.items = modules
    
    def filter(self, category: str = None) -> None:
        """Filter modules by category"""
        self.filter_category = category
        if category:
            self.items = [m for m in self.modules if m.category == category]
        else:
            self.items = self.modules
        self.selected = 0
        self.scroll_pos = 0
    
    def draw(self) -> None:
        """Draw modules list"""
        self.window.clear()
        self.draw_border()
        
        h, w = self.window.getmaxyx()
        
        # Category tabs
        categories = ["all", "exploits", "scanners", "dos", "aux"]
        tab_y = 1
        tab_x = 2
        for cat in categories:
            is_active = (cat == "all" and not self.filter_category) or cat == self.filter_category
            if is_active:
                self.window.attron(curses.color_pair(2) | curses.A_BOLD)
            self.window.addstr(tab_y, tab_x, f"[{cat}]")
            if is_active:
                self.window.attroff(curses.color_pair(2) | curses.A_BOLD)
            tab_x += len(cat) + 3
        
        if not self.items:
            self.window.addstr(h // 2, 2, "No modules", curses.A_DIM)
        else:
            # Modules list
            visible_start = self.scroll_pos
            visible_end = min(visible_start + h - 4, len(self.items))
            
            for i, module in enumerate(self.items[visible_start:visible_end]):
                y = i + 3
                idx = visible_start + i
                
                if idx == self.selected and self.focused:
                    self.window.attron(curses.A_REVERSE)
                
                # Category color
                if module.category == "exploits":
                    self.window.attron(curses.color_pair(5))
                elif module.category == "scanners":
                    self.window.attron(curses.color_pair(6))
                elif module.category == "dos":
                    self.window.attron(curses.color_pair(4))
                
                line = f"{module.name[:w-6]}"
                self.window.addstr(y, 2, line)
                
                self.window.attroff(curses.color_pair(5))
                self.window.attroff(curses.color_pair(6))
                self.window.attroff(curses.color_pair(4))
                
                if idx == self.selected and self.focused:
                    self.window.attroff(curses.A_REVERSE)
        
        self.window.refresh()


class OutputPanel(Panel):
    """Panel showing command output"""
    
    def __init__(self, window):
        super().__init__(window, "Output")
        self.lines: List[str] = []
        self.max_lines = 1000
    
    def add_line(self, text: str, color: int = 0) -> None:
        """Add output line"""
        self.lines.append((text, color))
        if len(self.lines) > self.max_lines:
            self.lines = self.lines[-self.max_lines:]
        
        # Auto-scroll to bottom
        h, _ = self.window.getmaxyx()
        visible = h - 2
        if len(self.lines) > visible:
            self.scroll_pos = len(self.lines) - visible
    
    def clear_output(self) -> None:
        """Clear output"""
        self.lines = []
        self.scroll_pos = 0
    
    def draw(self) -> None:
        """Draw output"""
        self.window.clear()
        self.draw_border()
        
        h, w = self.window.getmaxyx()
        visible = h - 2
        
        start = self.scroll_pos
        end = min(start + visible, len(self.lines))
        
        for i, (line, color) in enumerate(self.lines[start:end]):
            y = i + 1
            if color:
                self.window.attron(curses.color_pair(color))
            self.window.addstr(y, 1, line[:w-2])
            if color:
                self.window.attroff(curses.color_pair(color))
        
        self.window.refresh()


class StatusPanel(Panel):
    """Status bar panel"""
    
    def __init__(self, window):
        super().__init__(window, "")
        self.status = "Ready"
        self.module = None
        self.target = None
        self.stats = {}
    
    def set_status(self, status: str) -> None:
        self.status = status
    
    def set_module(self, module: str) -> None:
        self.module = module
    
    def set_target(self, target: str) -> None:
        self.target = target
    
    def set_stats(self, **kwargs) -> None:
        self.stats.update(kwargs)
    
    def draw(self) -> None:
        """Draw status bar"""
        self.window.clear()
        
        h, w = self.window.getmaxyx()
        
        # Left side: module and target
        left = ""
        if self.module:
            left += f"Module: {self.module}"
        if self.target:
            left += f" | Target: {self.target}"
        
        # Right side: stats
        right = ""
        if self.stats:
            right = " | ".join(f"{k}: {v}" for k, v in self.stats.items())
        
        # Center: status
        center = f"[ {self.status} ]"
        
        # Draw
        self.window.attron(curses.color_pair(1))
        self.window.addstr(0, 0, " " * w)
        self.window.addstr(0, 1, left[:w//3])
        
        center_x = (w - len(center)) // 2
        self.window.addstr(0, center_x, center)
        
        right_x = w - len(right) - 2
        if right_x > 0:
            self.window.addstr(0, right_x, right)
        
        self.window.attroff(curses.color_pair(1))
        self.window.refresh()


class HelpPanel(Panel):
    """Help panel with keybindings"""
    
    def __init__(self, window):
        super().__init__(window, "Help")
        self.keybindings = [
            ("Tab", "Switch panel"),
            ("↑/↓", "Navigate"),
            ("Enter", "Select/Run"),
            ("s", "Scan devices"),
            ("u", "Use module"),
            ("r", "Run module"),
            ("o", "Set options"),
            ("c", "Clear output"),
            ("t", "Change theme"),
            ("q", "Quit"),
            ("?", "Toggle help"),
        ]
    
    def draw(self) -> None:
        """Draw help"""
        self.window.clear()
        self.draw_border()
        
        h, w = self.window.getmaxyx()
        
        for i, (key, desc) in enumerate(self.keybindings):
            if i + 1 >= h - 1:
                break
            
            self.window.attron(curses.color_pair(2) | curses.A_BOLD)
            self.window.addstr(i + 1, 2, f"{key:>8}")
            self.window.attroff(curses.color_pair(2) | curses.A_BOLD)
            self.window.addstr(f"  {desc}")
        
        self.window.refresh()


class Dashboard:
    """
    Main TUI Dashboard for BlueSploit.
    
    Features:
    - Multi-panel layout
    - Device list
    - Module browser
    - Live output
    - Status bar
    - Keyboard navigation
    """
    
    def __init__(self):
        self.stdscr = None
        self.panels: Dict[PanelType, Panel] = {}
        self.focused_panel = PanelType.DEVICES
        self.running = False
        self.show_help = False
        
        # Callbacks
        self.on_scan: Optional[Callable] = None
        self.on_module_select: Optional[Callable[[str], None]] = None
        self.on_device_select: Optional[Callable[[str], None]] = None
        self.on_run: Optional[Callable] = None
    
    def _init_colors(self) -> None:
        """Initialize color pairs"""
        curses.start_color()
        curses.use_default_colors()
        
        # Color pairs
        curses.init_pair(1, curses.COLOR_CYAN, -1)     # Border
        curses.init_pair(2, curses.COLOR_GREEN, -1)    # Highlight
        curses.init_pair(3, curses.COLOR_GREEN, -1)    # Good RSSI
        curses.init_pair(4, curses.COLOR_YELLOW, -1)   # Medium RSSI
        curses.init_pair(5, curses.COLOR_RED, -1)      # Bad RSSI / Exploit
        curses.init_pair(6, curses.COLOR_BLUE, -1)     # Scanner
        curses.init_pair(7, curses.COLOR_MAGENTA, -1)  # Aux
    
    def _create_panels(self) -> None:
        """Create dashboard panels"""
        h, w = self.stdscr.getmaxyx()
        
        # Layout:
        # +------------------+------------------+
        # |    Devices       |    Modules       |
        # |                  |                  |
        # +------------------+------------------+
        # |             Output                  |
        # |                                     |
        # +-------------------------------------+
        # |            Status Bar               |
        # +-------------------------------------+
        
        # Calculate sizes
        top_h = h // 2 - 1
        bottom_h = h - top_h - 2
        left_w = w // 2
        right_w = w - left_w
        
        # Create windows
        devices_win = curses.newwin(top_h, left_w, 0, 0)
        modules_win = curses.newwin(top_h, right_w, 0, left_w)
        output_win = curses.newwin(bottom_h, w, top_h, 0)
        status_win = curses.newwin(1, w, h - 1, 0)
        help_win = curses.newwin(top_h, right_w, 0, left_w)
        
        # Create panels
        self.panels[PanelType.DEVICES] = DevicesPanel(devices_win)
        self.panels[PanelType.MODULES] = ModulesPanel(modules_win)
        self.panels[PanelType.OUTPUT] = OutputPanel(output_win)
        self.panels[PanelType.STATUS] = StatusPanel(status_win)
        self.panels[PanelType.HELP] = HelpPanel(help_win)
        
        # Set initial focus
        self.panels[self.focused_panel].focused = True
    
    def _handle_input(self, key: int) -> bool:
        """Handle keyboard input. Returns False to quit."""
        focused = self.panels[self.focused_panel]
        
        if key == ord('q'):
            return False
        
        elif key == ord('\t'):
            # Switch panel
            self.panels[self.focused_panel].focused = False
            
            if self.focused_panel == PanelType.DEVICES:
                self.focused_panel = PanelType.MODULES
            elif self.focused_panel == PanelType.MODULES:
                self.focused_panel = PanelType.OUTPUT
            else:
                self.focused_panel = PanelType.DEVICES
            
            self.panels[self.focused_panel].focused = True
        
        elif key == curses.KEY_UP:
            focused.scroll_up()
        
        elif key == curses.KEY_DOWN:
            focused.scroll_down()
        
        elif key == ord('\n'):
            # Select/Enter
            if self.focused_panel == PanelType.DEVICES:
                devices_panel = self.panels[PanelType.DEVICES]
                if devices_panel.devices and self.on_device_select:
                    device = devices_panel.devices[devices_panel.selected]
                    self.on_device_select(device.address)
            
            elif self.focused_panel == PanelType.MODULES:
                modules_panel = self.panels[PanelType.MODULES]
                if modules_panel.items and self.on_module_select:
                    module = modules_panel.items[modules_panel.selected]
                    self.on_module_select(module.name)
        
        elif key == ord('s'):
            # Scan
            if self.on_scan:
                self.on_scan()
        
        elif key == ord('r'):
            # Run
            if self.on_run:
                self.on_run()
        
        elif key == ord('c'):
            # Clear output
            self.panels[PanelType.OUTPUT].clear_output()
        
        elif key == ord('?'):
            # Toggle help
            self.show_help = not self.show_help
        
        return True
    
    def _draw(self) -> None:
        """Draw all panels"""
        self.panels[PanelType.DEVICES].draw()
        
        if self.show_help:
            self.panels[PanelType.HELP].draw()
        else:
            self.panels[PanelType.MODULES].draw()
        
        self.panels[PanelType.OUTPUT].draw()
        self.panels[PanelType.STATUS].draw()
    
    def add_device(self, device: Device) -> None:
        """Add device to display"""
        self.panels[PanelType.DEVICES].add_device(device)
    
    def set_modules(self, modules: List[ModuleInfo]) -> None:
        """Set modules list"""
        self.panels[PanelType.MODULES].set_modules(modules)
    
    def log(self, message: str, level: str = "info") -> None:
        """Add log message to output"""
        colors = {"info": 0, "success": 3, "warning": 4, "error": 5}
        color = colors.get(level, 0)
        self.panels[PanelType.OUTPUT].add_line(message, color)
    
    def set_status(self, status: str) -> None:
        """Set status bar text"""
        self.panels[PanelType.STATUS].set_status(status)
    
    def run(self, stdscr) -> None:
        """Main dashboard loop"""
        self.stdscr = stdscr
        
        # Setup
        curses.curs_set(0)  # Hide cursor
        self.stdscr.nodelay(True)  # Non-blocking input
        self._init_colors()
        self._create_panels()
        
        self.running = True
        
        # Add welcome message
        self.log("╔═══════════════════════════════════════════╗")
        self.log("║     BlueSploit TUI Dashboard v1.0        ║")
        self.log("║     Press ? for help                      ║")
        self.log("╚═══════════════════════════════════════════╝")
        self.log("")
        
        while self.running:
            # Draw
            self._draw()
            
            # Handle input
            try:
                key = self.stdscr.getch()
                if key != -1:
                    if not self._handle_input(key):
                        break
            except:
                pass
            
            time.sleep(0.05)
    
    def start(self) -> None:
        """Start the dashboard"""
        curses.wrapper(self.run)


def demo():
    """Demo the TUI dashboard"""
    dashboard = Dashboard()
    
    # Add sample modules
    modules = [
        ModuleInfo("exploits/bluefrag", "exploits", "Android RCE"),
        ModuleInfo("exploits/blueborne_leak", "exploits", "Info Leak"),
        ModuleInfo("scanners/ble_scanner", "scanners", "BLE Discovery"),
        ModuleInfo("scanners/vuln_scanner", "scanners", "CVE Detection"),
        ModuleInfo("dos/bluesmack", "dos", "L2CAP DoS"),
    ]
    
    # Add sample devices
    devices = [
        Device("AA:BB:CC:DD:EE:FF", "iPhone", -45, "Phone", [], time.time()),
        Device("11:22:33:44:55:66", "Galaxy S21", -62, "Phone", [], time.time()),
        Device("DE:AD:BE:EF:CA:FE", "ESP32", -78, "IoT", [], time.time()),
    ]
    
    def on_scan():
        dashboard.log("Starting scan...", "info")
        for d in devices:
            dashboard.add_device(d)
        dashboard.log("Scan complete: 3 devices found", "success")
    
    def on_module_select(name):
        dashboard.log(f"Selected module: {name}", "info")
        dashboard.set_status(f"Module: {name}")
    
    def on_device_select(addr):
        dashboard.log(f"Selected device: {addr}", "info")
    
    dashboard.on_scan = on_scan
    dashboard.on_module_select = on_module_select
    dashboard.on_device_select = on_device_select
    dashboard.set_modules(modules)
    
    dashboard.start()


if __name__ == "__main__":
    demo()
