"""
BlueSploit Printer Utilities
Professional UI for Bluetooth Exploitation Framework
"""

import os
import sys
import shutil
from datetime import datetime


class Colors:
    """ANSI color codes for terminal output"""
    # Basic colors
    BLACK = '\033[30m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Dark variants
    DARK_RED = '\033[31m'
    DARK_GREEN = '\033[32m'
    DARK_YELLOW = '\033[33m'
    DARK_BLUE = '\033[34m'
    DARK_MAGENTA = '\033[35m'
    DARK_CYAN = '\033[36m'
    DARK_GREY = '\033[90m'
    
    # Styles
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Background
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'


def get_terminal_width() -> int:
    """Get terminal width for centering"""
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80


def center_text(text: str, width: int = None) -> str:
    """Center text in terminal"""
    if width is None:
        width = get_terminal_width()
    import re
    clean = re.sub(r'\033\[[0-9;]*m', '', text)
    padding = (width - len(clean)) // 2
    return " " * max(0, padding) + text


def print_banner(version: str) -> None:
    """Display the professional BlueSploit banner"""
    
    C = Colors
    
    # Clear screen
    print("\033[2J\033[H", end="")
    
    banner = f"""
{C.CYAN}    ╔═════════════════════════════════════════════════════════════════════════════════╗
    ║                                                                                 ║
    ║  {C.BOLD}{C.WHITE}██████╗ ██╗     ██╗   ██╗███████╗{C.RED}███████╗██████╗ ██╗      ██████╗ ██╗████████╗{C.RESET}{C.CYAN} ║
    ║  {C.BOLD}{C.WHITE}██╔══██╗██║     ██║   ██║██╔════╝{C.RED}██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝{C.RESET}{C.CYAN} ║
    ║  {C.BOLD}{C.WHITE}██████╔╝██║     ██║   ██║█████╗  {C.RED}███████╗██████╔╝██║     ██║   ██║██║   ██║{C.RESET}{C.CYAN}    ║
    ║  {C.BOLD}{C.WHITE}██╔══██╗██║     ██║   ██║██╔══╝  {C.RED}╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║{C.RESET}{C.CYAN}    ║
    ║  {C.BOLD}{C.WHITE}██████╔╝███████╗╚██████╔╝███████╗{C.RED}███████║██║     ███████╗╚██████╔╝██║   ██║{C.RESET}{C.CYAN}    ║
    ║  {C.BOLD}{C.WHITE}╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝{C.RED}╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝{C.RESET}{C.CYAN}    ║
    ║                                                                                 ║
    ╠═════════════════════════════════════════════════════════════════════════════════╣
    ║                                                                                 ║
    ║  {C.BOLD}{C.WHITE}Bluetooth Exploitation Framework{C.RESET}{C.CYAN}                            {C.DARK_GREY}v{version:<8}{C.RESET}{C.CYAN}          ║
    ║  {C.DARK_GREY}─────────────────────────────────────────────────────────────────────────────{C.RESET}{C.CYAN}  ║
    ║                                                                                 ║
    ║  {C.YELLOW}◉{C.RESET}{C.CYAN} {C.WHITE}Author{C.RESET}{C.CYAN}    : {C.WHITE}v33ru / Mr-IoT{C.RESET}{C.CYAN}                                                   ║
    ║  {C.YELLOW}◉{C.RESET}{C.CYAN} {C.WHITE}Community{C.RESET}{C.CYAN} : {C.WHITE}IoT Security Research Group (IOTSRG){C.RESET}{C.CYAN}                             ║
    ║  {C.YELLOW}◉{C.RESET}{C.CYAN} {C.WHITE}GitHub{C.RESET}{C.CYAN}    : {C.DARK_CYAN}https://github.com/v33ru{C.RESET}{C.CYAN}                                         ║
    ║                                                                                 ║
    ╠═════════════════════════════════════════════════════════════════════════════════╣
    ║                                                                                 ║
    ║  {C.GREEN}[+]{C.RESET}{C.CYAN} BLE Scanning & Enumeration    {C.GREEN}[+]{C.RESET}{C.CYAN} GATT Service Analysis                    ║
    ║  {C.GREEN}[+]{C.RESET}{C.CYAN} Bluetooth Classic Attacks     {C.GREEN}[+]{C.RESET}{C.CYAN} Vulnerability Detection                  ║
    ║  {C.GREEN}[+]{C.RESET}{C.CYAN} Exploitation Modules          {C.GREEN}[+]{C.RESET}{C.CYAN} Protocol Reverse Engineering             ║
    ║                                                                                 ║
    ╚═════════════════════════════════════════════════════════════════════════════════╝{C.RESET}

    {C.DARK_GREY}┌─────────────────────────────────────────────────────────────────────────────┐{C.RESET}
    {C.DARK_GREY}│{C.RESET}  {C.YELLOW}{C.RESET} Type '{C.CYAN}help{C.RESET}' for commands    {C.YELLOW}{C.RESET} Type '{C.CYAN}show modules{C.RESET}' to list modules          {C.DARK_GREY}│{C.RESET}
    {C.DARK_GREY}└─────────────────────────────────────────────────────────────────────────────┘{C.RESET}
"""
    print(banner)


def print_banner_minimal(version: str) -> None:
    """Minimal banner for smaller terminals"""
    C = Colors
    
    banner = f"""
{C.CYAN}╔═══════════════════════════════════════════════════════╗
║  {C.BOLD}{C.WHITE}BLUESPLOIT{C.RESET}{C.CYAN} - Bluetooth Exploitation Framework     ║
║  {C.DARK_GREY}v{version} | by v33ru | IOTSRG{C.RESET}{C.CYAN}                         ║
╚═══════════════════════════════════════════════════════╝{C.RESET}
"""
    print(banner)


def print_module_banner(module_name: str, module_type: str) -> None:
    """Print banner when loading a module"""
    C = Colors
    
    type_colors = {
        "exploits": C.RED,
        "scanners": C.GREEN,
        "creds": C.YELLOW,
        "auxiliary": C.MAGENTA,
        "payloads": C.BLUE
    }
    
    color = type_colors.get(module_type, C.CYAN)
    
    print(f"""
{C.DARK_GREY}┌─────────────────────────────────────────────────────────┐{C.RESET}
{C.DARK_GREY}│{C.RESET} {color}◆{C.RESET} Module: {C.BOLD}{C.WHITE}{module_name}{C.RESET}
{C.DARK_GREY}│{C.RESET} {color}◆{C.RESET} Type  : {color}{module_type.upper()}{C.RESET}
{C.DARK_GREY}└─────────────────────────────────────────────────────────┘{C.RESET}
""")


def print_success(message: str) -> None:
    """Print a success message"""
    print(f"  {Colors.GREEN}[+]{Colors.RESET} {message}")


def print_error(message: str) -> None:
    """Print an error message"""
    print(f"  {Colors.RED}[✗]{Colors.RESET} {message}")


def print_warning(message: str) -> None:
    """Print a warning message"""
    print(f"  {Colors.YELLOW}[!]{Colors.RESET} {message}")


def print_info(message: str) -> None:
    """Print an info message"""
    print(f"  {Colors.CYAN}[*]{Colors.RESET} {message}")


def print_status(message: str) -> None:
    """Print a status message"""
    print(f"  {Colors.BLUE}[~]{Colors.RESET} {message}")


def print_debug(message: str) -> None:
    """Print debug message"""
    print(f"  {Colors.DARK_GREY}[D]{Colors.RESET} {Colors.DARK_GREY}{message}{Colors.RESET}")


def print_vuln(message: str, severity: str = "HIGH") -> None:
    """Print vulnerability found message"""
    sev_colors = {
        "CRITICAL": Colors.RED + Colors.BOLD,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.GREEN,
        "INFO": Colors.CYAN
    }
    color = sev_colors.get(severity.upper(), Colors.YELLOW)
    print(f"  {color}[VULN]{Colors.RESET} {message} {color}[{severity}]{Colors.RESET}")


def print_table(headers: list, rows: list, title: str = None) -> None:
    """Print a formatted table with borders"""
    C = Colors
    
    if not headers or not rows:
        return
    
    # Calculate column widths
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    
    # Total width
    total_width = sum(widths) + (len(widths) * 3) + 1
    
    # Print title if provided
    if title:
        print(f"\n  {C.CYAN}{'═' * total_width}{C.RESET}")
        print(f"  {C.CYAN}{C.BOLD}{title}{C.RESET}")
        print(f"  {C.CYAN}{'═' * total_width}{C.RESET}")
    
    # Print header
    header_line = f"  {C.DARK_GREY}│{C.RESET}"
    for i, h in enumerate(headers):
        header_line += f" {C.BOLD}{C.WHITE}{str(h):<{widths[i]}}{C.RESET} {C.DARK_GREY}│{C.RESET}"
    
    print(f"  {C.DARK_GREY}┌{'┬'.join('─' * (w + 2) for w in widths)}┐{C.RESET}")
    print(header_line)
    print(f"  {C.DARK_GREY}├{'┼'.join('─' * (w + 2) for w in widths)}┤{C.RESET}")
    
    # Print rows
    for row in rows:
        row_line = f"  {C.DARK_GREY}│{C.RESET}"
        for i, cell in enumerate(row):
            if i < len(widths):
                row_line += f" {str(cell):<{widths[i]}} {C.DARK_GREY}│{C.RESET}"
        print(row_line)
    
    print(f"  {C.DARK_GREY}└{'┴'.join('─' * (w + 2) for w in widths)}┘{C.RESET}")


def print_device(address: str, name: str = None, rssi: int = None, extra: str = None) -> None:
    """Print a discovered device"""
    C = Colors
    name_str = name if name else "Unknown"
    
    output = f"  {C.GREEN}[+]{C.RESET} {C.CYAN}{address}{C.RESET}"
    output += f" - {C.WHITE}{name_str}{C.RESET}"
    
    if rssi is not None:
        if rssi > -50:
            rssi_color = C.GREEN
        elif rssi > -70:
            rssi_color = C.YELLOW
        else:
            rssi_color = C.RED
        output += f" [{rssi_color}{rssi} dBm{C.RESET}]"
    
    if extra:
        output += f" {C.DARK_GREY}{extra}{C.RESET}"
    
    print(output)


def print_service(uuid: str, name: str = None, handle: int = None) -> None:
    """Print a discovered service"""
    C = Colors
    name_str = name if name else "Unknown Service"
    handle_str = f"0x{handle:04x}" if handle is not None else ""
    
    print(f"  {C.MAGENTA}├──◆ Service:{C.RESET} {C.WHITE}{uuid}{C.RESET} {C.DARK_GREY}{handle_str}{C.RESET}")
    print(f"  {C.DARK_GREY}│   └─ {name_str}{C.RESET}")


def print_characteristic(uuid: str, properties: list, handle: int = None, 
                         vuln_flag: str = None) -> None:
    """Print a discovered characteristic"""
    C = Colors
    handle_str = f"0x{handle:04x}" if handle is not None else ""
    props_str = ", ".join(properties) if properties else "none"
    
    print(f"  {C.CYAN}│   ├──○ Char:{C.RESET} {uuid} {C.DARK_GREY}{handle_str}{C.RESET}")
    print(f"  {C.DARK_GREY}│   │   Props: {props_str}{C.RESET}")
    
    if vuln_flag:
        print(f"  {C.RED}│   │   ⚠ {vuln_flag}{C.RESET}")


def progress_bar(current: int, total: int, prefix: str = "", suffix: str = "", 
                 length: int = 40) -> None:
    """Print a professional progress bar"""
    C = Colors
    
    percent = current / total if total > 0 else 0
    filled = int(length * percent)
    
    # Gradient effect
    bar = ""
    for i in range(length):
        if i < filled:
            if i < length * 0.3:
                bar += f"{C.RED}█{C.RESET}"
            elif i < length * 0.7:
                bar += f"{C.YELLOW}█{C.RESET}"
            else:
                bar += f"{C.GREEN}█{C.RESET}"
        else:
            bar += f"{C.DARK_GREY}░{C.RESET}"
    
    print(f"\r  {prefix} [{bar}] {C.WHITE}{percent*100:>5.1f}%{C.RESET} {suffix}", 
          end="", flush=True)
    
    if current >= total:
        print()


def print_section(title: str) -> None:
    """Print a section header"""
    C = Colors
    print(f"\n  {C.CYAN}{'─' * 60}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}{title}{C.RESET}")
    print(f"  {C.CYAN}{'─' * 60}{C.RESET}")


def print_box(content: list, title: str = None, color: str = None) -> None:
    """Print content in a box"""
    C = Colors
    if color is None:
        color = C.CYAN
    
    max_len = max(len(line) for line in content) if content else 20
    if title:
        max_len = max(max_len, len(title) + 4)
    
    print(f"\n  {color}╔{'═' * (max_len + 2)}╗{C.RESET}")
    
    if title:
        print(f"  {color}║{C.RESET} {C.BOLD}{C.WHITE}{title:<{max_len}}{C.RESET} {color}║{C.RESET}")
        print(f"  {color}╠{'═' * (max_len + 2)}╣{C.RESET}")
    
    for line in content:
        print(f"  {color}║{C.RESET} {line:<{max_len}} {color}║{C.RESET}")
    
    print(f"  {color}╚{'═' * (max_len + 2)}╝{C.RESET}")


def print_exploit_success(target: str, exploit: str) -> None:
    """Print exploit success banner"""
    C = Colors
    
    print(f"""
  {C.GREEN}╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║  {C.BOLD}{C.WHITE}★ ★ ★  EXPLOITATION SUCCESSFUL  ★ ★ ★{C.RESET}{C.GREEN}                  ║
  ║                                                          ║
  ║  {C.WHITE}Target  :{C.RESET}{C.GREEN} {target:<46} ║
  ║  {C.WHITE}Exploit :{C.RESET}{C.GREEN} {exploit:<46} ║
  ║                                                          ║
  ╚══════════════════════════════════════════════════════════╝{C.RESET}
""")


def print_scan_header(scan_type: str, target: str = None) -> None:
    """Print scan start header"""
    C = Colors
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"""
  {C.CYAN}┌─────────────────────────────────────────────────────────────┐{C.RESET}
  {C.CYAN}│{C.RESET} {C.BOLD}{C.WHITE}◉ {scan_type}{C.RESET}
  {C.CYAN}│{C.RESET} {C.DARK_GREY}Started: {timestamp}{C.RESET}
  {C.CYAN}│{C.RESET} {C.DARK_GREY}Target : {target or 'All nearby devices'}{C.RESET}
  {C.CYAN}└─────────────────────────────────────────────────────────────┘{C.RESET}
""")


def clear_line() -> None:
    """Clear the current line"""
    print("\r" + " " * get_terminal_width() + "\r", end="")
