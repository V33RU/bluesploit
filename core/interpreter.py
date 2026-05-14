"""
BlueSploit Command Interpreter
Provides the interactive Metasploit-style command-line interface
"""

import cmd
import readline
import sys
from typing import Any, Dict, List, Optional

from core.base import BaseModule, ModuleType
from core.loader import ModuleLoader
from core.utils.printer import (
    Colors,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)


class BlueSploitInterpreter(cmd.Cmd):
    """
    Interactive command interpreter for BlueSploit
    Provides Metasploit/RouterSploit-like interface for Bluetooth exploitation
    """

    doc_header = "Commands (type help <command>):"

    def __init__(self):
        super().__init__()
        self.loader = ModuleLoader()
        self.current_module: Optional[BaseModule] = None
        self._module_path: Optional[str] = None

        # Command history
        self.history_file = ".bluesploit_history"
        self._load_history()

        # Global options (applied to all modules via setg)
        self.global_options = {
            "interface": "hci0",
            "verbose": False,
            "timeout": 10,
            "pcap_file": None,
        }

        # Set initial prompt
        self._update_prompt()

    def _load_history(self) -> None:
        """Load command history from file"""
        try:
            readline.read_history_file(self.history_file)
        except FileNotFoundError:
            pass
        # Bind tab to completion (libedit on macOS, GNU readline elsewhere)
        try:
            if "libedit" in readline.__doc__:
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
        except Exception:
            pass
        # Treat '/' and '-' as part of words so module paths complete correctly
        try:
            delims = readline.get_completer_delims()
            for ch in "/-":
                delims = delims.replace(ch, "")
            readline.set_completer_delims(delims)
        except Exception:
            pass

    def _save_history(self) -> None:
        """Save command history to file"""
        try:
            readline.write_history_file(self.history_file)
        except Exception:
            pass

    def _update_prompt(self) -> None:
        """Update the command prompt based on current state and theme"""
        try:
            from core.ui.themes import get_theme
            theme = get_theme()
            if self.current_module:
                module_name = self._module_path or "unknown"
                self.prompt = (
                    f"{theme.prompt}bluesploit{theme.reset}"
                    f"({theme.error}{module_name}{theme.reset}) > "
                )
            else:
                self.prompt = f"{theme.prompt}bluesploit{theme.reset} > "
        except ImportError:
            # Fallback if themes not available
            if self.current_module:
                module_name = self._module_path or "unknown"
                self.prompt = f"{Colors.BLUE}bluesploit{Colors.RESET}({Colors.RED}{module_name}{Colors.RESET}) > "
            else:
                self.prompt = f"{Colors.BLUE}bluesploit{Colors.RESET} > "

    def precmd(self, line: str) -> str:
        """Pre-process command before execution"""
        return line.strip()

    def postcmd(self, stop: bool, line: str) -> bool:
        """Post-process after command execution"""
        self._update_prompt()
        return stop

    def emptyline(self) -> bool:
        """Handle empty line (do nothing)"""
        return False

    def default(self, line: str) -> None:
        """Handle unknown commands"""
        print_error(f"Unknown command: {line}")
        print_info("Type 'help' for available commands")

    # ==================== Core Commands ====================

    def do_use(self, module_path: str) -> None:
        """
        Load a module
        Usage: use <module_path>
        Example: use exploits/bluefrag
        """
        if not module_path:
            print_error("Usage: use <module_path>")
            print_info("Example: use exploits/bluefrag")
            return

        module = self.loader.load(module_path)
        if module:
            self.current_module = module
            # Resolve actual path (loader may have partial-matched)
            for path in self.loader.list_all():
                cached = self.loader.load(path)
                if cached is module:
                    self._module_path = path
                    break
            else:
                self._module_path = module_path
            print_success(f"Loaded module: {module.info.name}")
        else:
            print_error(f"Module not found: {module_path}")

    def complete_use(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for use command, matches full path or basename."""
        modules = self.loader.list_all()
        if not text:
            return modules
        # If text contains '/', match against full path prefix
        if "/" in text:
            return [m for m in modules if m.startswith(text)]
        # Otherwise match basename prefix OR substring anywhere
        prefix_hits = [m for m in modules if m.split("/")[-1].startswith(text)]
        if prefix_hits:
            return prefix_hits
        return [m for m in modules if text in m]

    def do_back(self, _: str) -> None:
        """Unload current module and return to main context"""
        if self.current_module:
            self.current_module = None
            self._module_path = None
            print_info("Module unloaded")
        else:
            print_warning("No module loaded")

    def do_set(self, args: str) -> None:
        """
        Set a module option
        Usage: set <option> <value>
        Example: set target AA:BB:CC:DD:EE:FF
        """
        if not self.current_module:
            print_error("No module loaded. Use 'use <module>' first")
            return

        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            print_error("Usage: set <option> <value>")
            return

        option, value = parts
        if self.current_module.set_option(option, value):
            print_success(f"{option} => {value}")
        else:
            print_error(f"Unknown option: {option}")

    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for set command"""
        if not self.current_module:
            return []

        options = list(self.current_module.options.keys())
        if text:
            return [o for o in options if o.lower().startswith(text.lower())]
        return options

    def do_unset(self, option: str) -> None:
        """
        Clear a module option
        Usage: unset <option>
        """
        if not self.current_module:
            print_error("No module loaded")
            return

        if not option:
            print_error("Usage: unset <option>")
            return

        if self.current_module.set_option(option, None):
            print_success(f"Cleared: {option}")
        else:
            print_error(f"Unknown option: {option}")

    def do_options(self, _: str) -> None:
        """Show current module options"""
        if not self.current_module:
            print_error("No module loaded. Use 'use <module>' first")
            return

        self.current_module.show_options()

    def do_info(self, _: str) -> None:
        """Show detailed information about current module"""
        if not self.current_module:
            print_error("No module loaded")
            return

        self.current_module.show_info()

    def do_run(self, _: str) -> None:
        """Execute the current module"""
        if not self.current_module:
            print_error("No module loaded. Use 'use <module>' first")
            return

        # Apply global pcap_file if set and module doesn't have one
        global_pcap = self.global_options.get("pcap_file")
        if global_pcap and not self.current_module.get_option("pcap_file"):
            self.current_module.set_option("pcap_file", global_pcap)

        if not self.current_module.validate_options():
            print_error("Required options not set. Use 'options' to see required options")
            return

        print_status(f"Running {self.current_module.info.name}...")
        print()

        try:
            success = self.current_module.execute()
            print()
            if success:
                print_success("Module execution completed")
            else:
                print_warning("Module execution completed with issues")
        except KeyboardInterrupt:
            print()
            print_warning("Module execution interrupted")
        except Exception as e:
            print()
            print_error(f"Module execution failed: {e}")
            if self.global_options.get("verbose"):
                import traceback
                traceback.print_exc()

    def do_exploit(self, _: str) -> None:
        """Alias for 'run' command"""
        self.do_run(_)

    def do_check(self, _: str) -> None:
        """Check if target is vulnerable (exploit modules only)"""
        if not self.current_module:
            print_error("No module loaded")
            return

        if hasattr(self.current_module, 'check'):
            print_status("Checking target...")
            try:
                result = self.current_module.check()
                if result:
                    print_success("Target appears to be vulnerable!")
                else:
                    print_info("Target does not appear vulnerable")
            except Exception as e:
                print_error(f"Check failed: {e}")
        else:
            print_warning("Check not available for this module type")

    # ==================== Search/List Commands ====================

    def do_search(self, query: str) -> None:
        """
        Search for modules by name, description, or CVE
        Usage: search <keyword>
        Example: search bluefrag
        Example: search CVE-2020-0022
        """
        if not query:
            print_error("Usage: search <keyword>")
            return

        results = self.loader.search_deep(query)

        if not results:
            print_warning(f"No modules found matching: {query}")
            return

        print(f"\n  Found {len(results)} module(s):\n")
        for module_path in results:
            module = self.loader.load(module_path)
            if module:
                severity = module.info.severity.value.upper()
                cve_str = ""
                if module.info.cve:
                    cve_list = module.info.cve if isinstance(module.info.cve, list) else [module.info.cve]
                    cve_str = f" ({', '.join(cve_list)})"
                print(f"  {module_path:<40} {severity:<8} {module.info.description}{cve_str}")
            else:
                print(f"  {module_path:<40} {'?':<8} (failed to load)")
        print()

    def do_show(self, args: str) -> None:
        """
        Show various information
        Usage: show <type>
        Types: modules, scanners, exploits, dos, recon, creds, auxiliary, options
        """
        args = args.lower().strip()

        if args == "modules" or args == "all":
            self._show_all_modules()
        elif args == "scanners":
            self._show_modules_by_type(ModuleType.SCANNER)
        elif args == "exploits":
            self._show_modules_by_type(ModuleType.EXPLOIT)
        elif args == "dos":
            self._show_modules_by_type(ModuleType.DOS)
        elif args == "recon":
            self._show_modules_by_type(ModuleType.RECON)
        elif args == "creds":
            self._show_modules_by_type(ModuleType.CREDS)
        elif args == "auxiliary":
            self._show_modules_by_type(ModuleType.AUXILIARY)
        elif args == "payloads":
            self._show_modules_by_type(ModuleType.PAYLOAD)
        elif args == "options":
            self.do_options("")
        else:
            print_error("Usage: show <modules|scanners|exploits|dos|recon|creds|auxiliary|payloads|options>")

    def complete_show(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for show command"""
        options = [
            "modules", "scanners", "exploits", "dos", "recon",
            "creds", "auxiliary", "payloads", "options",
        ]
        if text:
            return [o for o in options if o.startswith(text.lower())]
        return options

    def _show_all_modules(self) -> None:
        """Display all available modules grouped by category"""
        modules = self.loader.list_all()

        if not modules:
            print_warning("No modules available")
            return

        stats = self.loader.stats()
        print(f"\n  Available modules: {len(modules)}")
        for mod_type, count in sorted(stats.items()):
            print(f"    {mod_type}: {count}")
        print()

        # Group by category
        categories: Dict[str, List[str]] = {}
        for module_path in modules:
            category = module_path.split('/')[0]
            if category not in categories:
                categories[category] = []
            categories[category].append(module_path)

        for category in sorted(categories.keys()):
            print(f"  {Colors.CYAN}{category.upper()}{Colors.RESET}")
            print(f"  {'=' * 70}")
            for module_path in categories[category]:
                module = self.loader.load(module_path)
                if module:
                    severity = module.info.severity.value.upper()
                    print(f"  {module_path:<40} {severity:<8} {module.info.description}")
            print()

    def _show_modules_by_type(self, module_type: ModuleType) -> None:
        """Display modules of a specific type"""
        modules = self.loader.list_by_type(module_type)

        if not modules:
            print_warning(f"No {module_type.value} modules available")
            return

        print(f"\n  {module_type.value.title()} modules ({len(modules)}):\n")
        for module_path in modules:
            module = self.loader.load(module_path)
            if module:
                severity = module.info.severity.value.upper()
                print(f"  {module_path:<40} {severity:<8} {module.info.description}")
        print()

    # ==================== Utility Commands ====================

    def do_clear(self, _: str) -> None:
        """Clear the terminal screen"""
        print("\033[2J\033[H", end="")

    def do_banner(self, _: str) -> None:
        """Display the BlueSploit banner"""
        from core.utils.printer import print_banner
        print_banner("1.0.0")
        print_info(f"Loaded {self.loader.module_count} modules")
        print()

    def do_reload(self, _: str) -> None:
        """Reload all modules (useful during development)"""
        print_status("Reloading modules...")
        self.loader.refresh()
        print_success(f"Indexed {self.loader.module_count} modules")

    def do_setg(self, args: str) -> None:
        """
        Set a global option
        Usage: setg <option> <value>
        """
        parts = args.split(maxsplit=1)
        if len(parts) < 2:
            print("  Global options:")
            for k, v in self.global_options.items():
                print(f"    {k}: {v}")
            return

        option, raw_value = parts
        if option in self.global_options:
            coerced: Any = raw_value
            if isinstance(self.global_options[option], bool):
                coerced = raw_value.lower() in ('true', '1', 'yes')
            elif isinstance(self.global_options[option], int):
                try:
                    coerced = int(raw_value)
                except ValueError:
                    print_error(f"Invalid integer value: {raw_value}")
                    return

            self.global_options[option] = coerced
            print_success(f"Global: {option} => {coerced}")
        else:
            print_error(f"Unknown global option: {option}")

    def do_help(self, arg: str) -> None:
        """Show help information"""
        if arg:
            super().do_help(arg)
        else:
            print(f"""
  {Colors.CYAN}Core Commands{Colors.RESET}
  =============
    use <module>      Load a module
    back              Unload current module
    search <keyword>  Search modules (name, description, CVE)
    show <type>       Show modules/options

  {Colors.CYAN}Module Commands{Colors.RESET}
  ===============
    set <opt> <val>   Set module option
    unset <option>    Clear module option
    options           Show module options
    info              Show module info
    run / exploit     Execute module
    check             Check if vulnerable

  {Colors.CYAN}Utility Commands{Colors.RESET}
  ================
    clear             Clear screen
    reload            Reload modules
    setg <opt> <val>  Set global option
    banner            Show banner
    exit / quit       Exit BlueSploit
""")

    def do_exit(self, _: str) -> bool:
        """Exit BlueSploit"""
        self._save_history()
        print_info("Goodbye!")
        return True

    def do_quit(self, _: str) -> bool:
        """Exit BlueSploit (alias for exit)"""
        return self.do_exit(_)

    def do_EOF(self, _: str) -> bool:
        """Handle Ctrl+D"""
        print()
        return self.do_exit(_)
