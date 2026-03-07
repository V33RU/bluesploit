#!/usr/bin/env python3
"""
BlueSploit - Bluetooth Exploitation Framework
A Metasploit/RouterSploit-style framework for Bluetooth security testing

Author: v33ru (IOTSRG)
License: MIT

Usage:
    python bluesploit.py                  # Start interactive console
    python bluesploit.py --theme hacker   # With color theme
    python bluesploit.py --web            # Start web interface
    python bluesploit.py --list           # List all modules
"""

import sys
import argparse

__version__ = "0.0.1"


def main():
    """Main entry point for BlueSploit"""
    from core.ui.themes import set_theme, THEMES

    parser = argparse.ArgumentParser(
        description="BlueSploit - Bluetooth Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python bluesploit.py                    Start console\n"
               "  python bluesploit.py --theme hacker     Green theme\n"
               "  python bluesploit.py --web --port 8080  Web UI on port 8080\n"
               "  python bluesploit.py --list             List modules\n",
    )
    parser.add_argument(
        "--theme",
        choices=list(THEMES.keys()),
        default="default",
        help="Color theme (default: default)",
    )
    parser.add_argument("--web", action="store_true", help="Start web interface")
    parser.add_argument("--port", type=int, default=5000, help="Web UI port (default: 5000)")
    parser.add_argument("--list", action="store_true", dest="list_modules", help="List all modules and exit")

    args = parser.parse_args()

    # Apply theme
    set_theme(args.theme)

    if args.list_modules:
        _list_modules()
    elif args.web:
        _start_web(args.port)
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


def _start_web(port: int):
    """Start the web interface"""
    try:
        from core.ui.webui import WebUI, FLASK_AVAILABLE
    except ImportError:
        FLASK_AVAILABLE = False

    if not FLASK_AVAILABLE:
        print("  [\033[91m!\033[0m] Flask not installed. Install: pip install flask flask-cors")
        print("  [\033[94m*\033[0m] Falling back to console mode...\n")
        _start_console()
        return

    from core.loader import ModuleLoader

    loader = ModuleLoader()
    web = WebUI(port=port)

    # Populate web UI with module data
    modules_data = []
    for path in loader.list_all():
        mod = loader.load(path)
        if mod:
            category = path.split("/")[0]
            options = {}
            for opt_name, opt in mod.options.items():
                options[opt_name] = {
                    "required": opt.required,
                    "default": str(opt.default) if opt.default is not None else "",
                    "description": opt.description,
                }
            modules_data.append({
                "name": path,
                "category": category,
                "description": mod.info.description,
                "options": options,
            })

    web.set_modules(modules_data)

    def on_run(module_path, options):
        """Callback for web UI module execution"""
        mod = loader.load(module_path)
        if not mod:
            return {"output": [f"Module not found: {module_path}"]}

        for k, v in options.items():
            mod.set_option(k, v)

        if not mod.validate_options():
            return {"output": ["Required options not set"]}

        try:
            mod.run()
            return {"output": ["Module executed successfully"]}
        except Exception as e:
            return {"output": [f"Error: {e}"]}

    web.on_run = on_run

    print(f"\n  [\033[92m+\033[0m] BlueSploit Web UI: http://127.0.0.1:{port}")
    print(f"  [\033[94m*\033[0m] {loader.module_count} modules available")
    print("  [\033[94m*\033[0m] Press Ctrl+C to stop\n")

    try:
        web.start(background=False)
    except KeyboardInterrupt:
        print("\n  Shutting down...")


if __name__ == "__main__":
    main()
