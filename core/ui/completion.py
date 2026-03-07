"""
BlueSploit UI: Enhanced Tab Completion
Advanced command auto-completion with context awareness

Author: v33ru
"""

import os
import readline
import glob
from typing import List, Dict, Optional, Callable


class TabCompleter:
    """
    Advanced tab completion for BlueSploit console.
    
    Features:
    - Command completion
    - Module path completion
    - Option name completion
    - Option value completion (files, addresses, etc.)
    - Context-aware suggestions
    """
    
    def __init__(self):
        self.commands = []
        self.modules = []
        self.current_options = {}
        self.option_values = {}
        self.context = "main"  # main, module, etc.
        self.current_module = None
        
        # Common value patterns
        self.bd_addr_pattern = "XX:XX:XX:XX:XX:XX"
        self.common_values = {
            "timeout": ["5", "10", "15", "30", "60"],
            "mode": ["check", "crash", "exploit", "analyze"],
            "protocol": ["auto", "classic", "ble"],
            "threads": ["1", "5", "10", "20"],
            "interface": ["hci0", "hci1"],
        }
    
    def set_commands(self, commands: List[str]) -> None:
        """Set available commands"""
        self.commands = sorted(commands)
    
    def set_modules(self, modules: List[str]) -> None:
        """Set available modules"""
        self.modules = sorted(modules)
    
    def set_current_options(self, options: Dict) -> None:
        """Set options for current module"""
        self.current_options = options
    
    def set_context(self, context: str, module: str = None) -> None:
        """Set completion context"""
        self.context = context
        self.current_module = module
    
    def _get_module_completions(self, text: str) -> List[str]:
        """Get module path completions"""
        if not text:
            # Show top-level categories
            categories = set()
            for mod in self.modules:
                parts = mod.split("/")
                if parts:
                    categories.add(parts[0] + "/")
            return sorted(categories)
        
        matches = []
        for mod in self.modules:
            if mod.startswith(text):
                matches.append(mod)
            elif "/" in text:
                # Partial path match
                if text in mod:
                    matches.append(mod)
        
        # If exact category match, show subcategories/modules
        if text.endswith("/"):
            prefix = text
            for mod in self.modules:
                if mod.startswith(prefix):
                    remainder = mod[len(prefix):]
                    if "/" in remainder:
                        # Subcategory
                        subcat = remainder.split("/")[0] + "/"
                        full = prefix + subcat
                        if full not in matches:
                            matches.append(full)
                    else:
                        matches.append(mod)
        
        return sorted(set(matches))
    
    def _get_option_completions(self, text: str) -> List[str]:
        """Get option name completions"""
        matches = []
        for opt in self.current_options.keys():
            if opt.startswith(text):
                matches.append(opt)
        return sorted(matches)
    
    def _get_value_completions(self, option: str, text: str) -> List[str]:
        """Get option value completions"""
        matches = []
        
        # Check for common value patterns
        opt_lower = option.lower()
        
        # BD_ADDR completion
        if any(x in opt_lower for x in ["target", "victim", "address", "addr"]):
            if not text:
                matches.append(self.bd_addr_pattern)
            # Could add recently used addresses here
        
        # File path completion
        elif any(x in opt_lower for x in ["file", "path", "output", "input"]):
            if text:
                matches.extend(glob.glob(text + "*"))
            else:
                matches.extend(glob.glob("*"))
        
        # Boolean completion
        elif any(x in opt_lower for x in ["enable", "disable", "verbose", "debug", "active", "deep"]):
            for val in ["true", "false", "yes", "no", "1", "0"]:
                if val.startswith(text.lower()):
                    matches.append(val)
        
        # Common option values
        elif opt_lower in self.common_values:
            for val in self.common_values[opt_lower]:
                if val.startswith(text):
                    matches.append(val)
        
        # Check module-specific values
        if option in self.option_values:
            for val in self.option_values[option]:
                if str(val).startswith(text):
                    matches.append(str(val))
        
        return matches
    
    def _get_command_completions(self, text: str) -> List[str]:
        """Get command completions"""
        matches = []
        for cmd in self.commands:
            if cmd.startswith(text):
                matches.append(cmd)
        return sorted(matches)
    
    def complete(self, text: str, state: int) -> Optional[str]:
        """Main completion function for readline"""
        try:
            line = readline.get_line_buffer()
            words = line.split()
            
            # Determine what to complete
            if not words or (len(words) == 1 and not line.endswith(" ")):
                # Completing command
                matches = self._get_command_completions(text)
            
            elif words[0] in ["use", "load", "info"]:
                # Completing module path
                matches = self._get_module_completions(text)
            
            elif words[0] == "set":
                if len(words) == 1 or (len(words) == 2 and not line.endswith(" ")):
                    # Completing option name
                    matches = self._get_option_completions(text)
                else:
                    # Completing option value
                    option = words[1] if len(words) >= 2 else ""
                    matches = self._get_value_completions(option, text)
            
            elif words[0] == "show":
                # Show subcommands
                subcommands = ["options", "info", "modules", "exploits", "scanners", 
                              "auxiliary", "all", "results", "history"]
                matches = [s for s in subcommands if s.startswith(text)]
            
            elif words[0] == "help":
                # Help topics
                matches = self._get_command_completions(text)
            
            else:
                # Default to command completion
                matches = self._get_command_completions(text)
            
            # Return match by state
            if state < len(matches):
                return matches[state]
            return None
            
        except Exception:
            return None
    
    def setup_readline(self) -> None:
        """Configure readline for tab completion"""
        readline.set_completer(self.complete)
        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        
        # Enable history navigation
        readline.parse_and_bind('"\e[A": history-search-backward')
        readline.parse_and_bind('"\e[B": history-search-forward')


class CommandHistory:
    """
    Persistent command history manager.
    
    Features:
    - Save history to file
    - Load history on startup
    - Search history
    - Limit history size
    """
    
    def __init__(self, history_file: str = None, max_size: int = 1000):
        self.history_file = history_file or os.path.expanduser("~/.bluesploit_history")
        self.max_size = max_size
        self.history = []
    
    def load(self) -> None:
        """Load history from file"""
        try:
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)
                
                # Also load into our list
                with open(self.history_file, 'r') as f:
                    self.history = [line.strip() for line in f.readlines()]
                    self.history = self.history[-self.max_size:]
        except Exception:
            pass
    
    def save(self) -> None:
        """Save history to file"""
        try:
            readline.set_history_length(self.max_size)
            readline.write_history_file(self.history_file)
        except Exception:
            pass
    
    def add(self, command: str) -> None:
        """Add command to history"""
        if command and command.strip():
            command = command.strip()
            # Don't add duplicates of last command
            if not self.history or self.history[-1] != command:
                self.history.append(command)
                readline.add_history(command)
                
                # Trim if needed
                if len(self.history) > self.max_size:
                    self.history = self.history[-self.max_size:]
    
    def search(self, pattern: str) -> List[str]:
        """Search history for pattern"""
        matches = []
        for cmd in reversed(self.history):
            if pattern.lower() in cmd.lower():
                matches.append(cmd)
        return matches
    
    def get_recent(self, count: int = 10) -> List[str]:
        """Get recent commands"""
        return self.history[-count:]
    
    def clear(self) -> None:
        """Clear history"""
        self.history = []
        readline.clear_history()
        try:
            if os.path.exists(self.history_file):
                os.remove(self.history_file)
        except:
            pass


# Global instances
completer = TabCompleter()
history = CommandHistory()


def setup_completion(commands: List[str], modules: List[str]) -> None:
    """Setup tab completion and history"""
    completer.set_commands(commands)
    completer.set_modules(modules)
    completer.setup_readline()
    history.load()


def save_history() -> None:
    """Save history on exit"""
    history.save()
