#!/usr/bin/env python3
"""
BlueSploit - Bluetooth Exploitation Framework
A Metasploit/RouterSploit-style framework for Bluetooth security testing

Author: Mr-IoT (Mr-IoT)
License: MIT

Usage:
    python bluesploit.py                  # Start interactive console
    python bluesploit.py --list           # List all modules
"""

import argparse
import sys

__version__ = "1.0.2.dev0"


def main():
    """Main entry point for BlueSploit"""
    parser = argparse.ArgumentParser(
        description="BlueSploit - Bluetooth Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python bluesploit.py          Start console\n"
               "  python bluesploit.py --list   List modules\n",
    )
    parser.add_argument("--list", action="store_true", dest="list_modules", help="List all modules and exit")

    args = parser.parse_args()

    if args.list_modules:
        _list_modules()
    else:
        _start_console()


def _list_modules():
    """List all available modules and exit"""
    from core.loader import ModuleLoader

    loader = ModuleLoader()
    stats = loader.stats()

    print(f"\n  BlueSploit v{__version__} - Available Modules ({loader.module_count})\n")

    for mod_type, count in sorted(stats.items()):
        print(f"    {mod_type}: {count}")
    print()

    for path in loader.list_all():
        mod = loader.load(path)
        if mod:
            print(f"  {path:<40} {mod.info.description}")
        else:
            print(f"  {path:<40} (failed to load)")
    print()


def _start_console():
    """Start the interactive console"""
    from core.interpreter import BlueSploitInterpreter
    from core.utils.printer import print_banner, print_info

    print_banner(__version__)

    interp = BlueSploitInterpreter()
    print_info(f"Loaded {interp.loader.module_count} modules")
    print()

    try:
        interp.cmdloop()
    except KeyboardInterrupt:
        print("\n")
        from core.utils.printer import print_info as pi
        pi("Goodbye!")


if __name__ == "__main__":
    main()
