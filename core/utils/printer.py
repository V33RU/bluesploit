"""
BlueSploit Printer Utilities
Provides colored console output and banner display
"""


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


def print_banner(version: str) -> None:
    """Display the BlueSploit banner"""
    banner = f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════════╗
║{Colors.RESET}                                                              {Colors.BLUE}║
║{Colors.CYAN}   ██████╗ ██╗     ██╗   ██╗███████╗███████╗██████╗ ██╗      {Colors.BLUE}║
║{Colors.CYAN}   ██╔══██╗██║     ██║   ██║██╔════╝██╔════╝██╔══██╗██║      {Colors.BLUE}║
║{Colors.CYAN}   ██████╔╝██║     ██║   ██║█████╗  ███████╗██████╔╝██║      {Colors.BLUE}║
║{Colors.CYAN}   ██╔══██╗██║     ██║   ██║██╔══╝  ╚════██║██╔═══╝ ██║      {Colors.BLUE}║
║{Colors.CYAN}   ██████╔╝███████╗╚██████╔╝███████╗███████║██║     ███████╗ {Colors.BLUE}║
║{Colors.CYAN}   ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝ {Colors.BLUE}║
║{Colors.RESET}                                                              {Colors.BLUE}║
║{Colors.WHITE}        Bluetooth Exploitation Framework v{version:<8}          {Colors.BLUE}║
║{Colors.DIM}                   by v33ru / Mr-IoT                           {Colors.BLUE}║
║{Colors.DIM}                        IOTSRG                                  {Colors.BLUE}║
║{Colors.RESET}                                                              {Colors.BLUE}║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}

    {Colors.YELLOW}[*]{Colors.RESET} Type 'help' to see available commands
    {Colors.YELLOW}[*]{Colors.RESET} Type 'show modules' to list all modules
"""
    print(banner)


def print_success(message: str) -> None:
    """Print a success message in green"""
    print(f"[{Colors.GREEN}+{Colors.RESET}] {message}")


def print_error(message: str) -> None:
    """Print an error message in red"""
    print(f"[{Colors.RED}!{Colors.RESET}] {message}")


def print_warning(message: str) -> None:
    """Print a warning message in yellow"""
    print(f"[{Colors.YELLOW}!{Colors.RESET}] {message}")


def print_info(message: str) -> None:
    """Print an info message in cyan"""
    print(f"[{Colors.CYAN}*{Colors.RESET}] {message}")


def print_status(message: str) -> None:
    """Print a status message"""
    print(f"[{Colors.BLUE}*{Colors.RESET}] {message}")


def print_table(headers: list, rows: list, padding: int = 2) -> None:
    """
    Print a formatted table
    
    Args:
        headers: List of column headers
        rows: List of rows (each row is a list of values)
        padding: Padding between columns
    """
    if not headers or not rows:
        return
    
    # Calculate column widths
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    
    # Print header
    header_line = "  ".join(f"{str(h):<{widths[i]}}" for i, h in enumerate(headers))
    print(f"  {header_line}")
    print("  " + "-" * (sum(widths) + (len(widths) - 1) * 2))
    
    # Print rows
    for row in rows:
        row_line = "  ".join(f"{str(cell):<{widths[i]}}" for i, cell in enumerate(row))
        print(f"  {row_line}")


def print_device(address: str, name: str = None, rssi: int = None, extra: str = None) -> None:
    """
    Print a discovered device in a formatted way
    
    Args:
        address: BD_ADDR
        name: Device name (optional)
        rssi: Signal strength (optional)
        extra: Additional info (optional)
    """
    name_str = name if name else "Unknown"
    
    output = f"[{Colors.GREEN}+{Colors.RESET}] {Colors.CYAN}{address}{Colors.RESET}"
    output += f" - {Colors.WHITE}{name_str}{Colors.RESET}"
    
    if rssi is not None:
        # Color code RSSI
        if rssi > -50:
            rssi_color = Colors.GREEN
        elif rssi > -70:
            rssi_color = Colors.YELLOW
        else:
            rssi_color = Colors.RED
        output += f" [{rssi_color}{rssi} dBm{Colors.RESET}]"
    
    if extra:
        output += f" {Colors.DIM}{extra}{Colors.RESET}"
    
    print(output)


def print_service(uuid: str, name: str = None, handle: int = None) -> None:
    """Print a discovered service"""
    name_str = name if name else "Unknown Service"
    handle_str = f"(0x{handle:04x})" if handle is not None else ""
    print(f"  {Colors.MAGENTA}├── Service:{Colors.RESET} {uuid} {handle_str}")
    print(f"  {Colors.DIM}│   {name_str}{Colors.RESET}")


def print_characteristic(uuid: str, properties: list, handle: int = None, 
                         vuln_flag: str = None) -> None:
    """Print a discovered characteristic"""
    handle_str = f"(0x{handle:04x})" if handle is not None else ""
    props_str = ", ".join(properties) if properties else "none"
    
    print(f"  {Colors.CYAN}│   ├── Char:{Colors.RESET} {uuid} {handle_str}")
    print(f"  {Colors.DIM}│   │   Properties: {props_str}{Colors.RESET}")
    
    if vuln_flag:
        print(f"  {Colors.RED}│   │   ⚠ {vuln_flag}{Colors.RESET}")


def progress_bar(current: int, total: int, prefix: str = "", suffix: str = "", 
                 length: int = 50) -> None:
    """
    Print a progress bar
    
    Args:
        current: Current progress
        total: Total items
        prefix: Prefix string
        suffix: Suffix string
        length: Bar length in characters
    """
    percent = current / total if total > 0 else 0
    filled = int(length * percent)
    bar = "█" * filled + "░" * (length - filled)
    
    print(f"\r  {prefix} [{Colors.CYAN}{bar}{Colors.RESET}] {percent*100:.1f}% {suffix}", 
          end="", flush=True)
    
    if current >= total:
        print()
