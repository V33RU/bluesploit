#!/usr/bin/env python3
"""
BlueSploit - Bluetooth Exploitation Framework
Author: v33ru / Mr-IoT (IOTSRG)
Description: Metasploit-style framework for Bluetooth Classic and BLE security testing
"""

import sys
import argparse
from core.interpreter import BlueSploitInterpreter
from core.utils.printer import print_banner

__version__ = "1.0.0"
__author__ = "v33ru"

def main():
    parser = argparse.ArgumentParser(
        description="BlueSploit - Bluetooth Exploitation Framework"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (no banner)"
    )
    parser.add_argument(
        "-m", "--module",
        type=str,
        help="Directly load a module"
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"BlueSploit v{__version__}"
    )
    
    args = parser.parse_args()
    
    if not args.quiet:
        print_banner(__version__)
    
    try:
        interpreter = BlueSploitInterpreter()
        
        # If module specified via CLI, load it
        if args.module:
            interpreter.do_use(args.module)
        
        interpreter.cmdloop()
        
    except KeyboardInterrupt:
        print("\n[*] Exiting BlueSploit...")
        sys.exit(0)

if __name__ == "__main__":
    main()
