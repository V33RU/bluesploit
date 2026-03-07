"""
BlueSploit UI: Themes System
Customizable color themes for the console interface

Author: v33ru
"""

import os
import json
from typing import Dict, Optional
from dataclasses import dataclass, field, asdict


@dataclass
class Theme:
    """Color theme definition"""
    name: str
    description: str
    
    # Base colors
    primary: str = "\033[96m"      # Cyan
    secondary: str = "\033[95m"    # Magenta
    accent: str = "\033[93m"       # Yellow
    
    # Status colors
    success: str = "\033[92m"      # Green
    error: str = "\033[91m"        # Red
    warning: str = "\033[93m"      # Yellow
    info: str = "\033[94m"         # Blue
    
    # Text colors
    text: str = "\033[97m"         # White
    text_dim: str = "\033[90m"     # Dark grey
    text_bold: str = "\033[1m"     # Bold
    
    # UI elements
    prompt: str = "\033[91m"       # Red
    prompt_arrow: str = "\033[97m" # White
    border: str = "\033[96m"       # Cyan
    header: str = "\033[1;97m"     # Bold white
    
    # Module types
    exploit: str = "\033[91m"      # Red
    scanner: str = "\033[94m"      # Blue
    auxiliary: str = "\033[93m"    # Yellow
    dos: str = "\033[95m"          # Magenta
    
    # Reset
    reset: str = "\033[0m"


# Built-in themes
THEMES: Dict[str, Theme] = {
    "default": Theme(
        name="default",
        description="Default BlueSploit theme (cyan/red)"
    ),
    
    "hacker": Theme(
        name="hacker",
        description="Classic green-on-black hacker aesthetic",
        primary="\033[92m",        # Green
        secondary="\033[32m",      # Dark green
        accent="\033[97m",         # White
        success="\033[92m",        # Green
        error="\033[91m",          # Red
        warning="\033[93m",        # Yellow
        info="\033[92m",           # Green
        text="\033[92m",           # Green
        text_dim="\033[32m",       # Dark green
        prompt="\033[92m",         # Green
        prompt_arrow="\033[97m",   # White
        border="\033[32m",         # Dark green
        header="\033[1;92m",       # Bold green
        exploit="\033[91m",
        scanner="\033[92m",
        auxiliary="\033[93m",
        dos="\033[95m"
    ),
    
    "ocean": Theme(
        name="ocean",
        description="Cool blue ocean tones",
        primary="\033[94m",        # Blue
        secondary="\033[96m",      # Cyan
        accent="\033[97m",         # White
        success="\033[96m",        # Cyan
        error="\033[91m",          # Red
        warning="\033[93m",        # Yellow
        info="\033[94m",           # Blue
        text="\033[97m",           # White
        text_dim="\033[90m",       # Grey
        prompt="\033[94m",         # Blue
        prompt_arrow="\033[96m",   # Cyan
        border="\033[94m",         # Blue
        header="\033[1;96m",       # Bold cyan
        exploit="\033[91m",
        scanner="\033[94m",
        auxiliary="\033[96m",
        dos="\033[95m"
    ),
    
    "fire": Theme(
        name="fire",
        description="Hot red and orange tones",
        primary="\033[91m",        # Red
        secondary="\033[93m",      # Yellow
        accent="\033[97m",         # White
        success="\033[92m",        # Green
        error="\033[91m",          # Red
        warning="\033[93m",        # Yellow
        info="\033[91m",           # Red
        text="\033[97m",           # White
        text_dim="\033[90m",       # Grey
        prompt="\033[91m",         # Red
        prompt_arrow="\033[93m",   # Yellow
        border="\033[91m",         # Red
        header="\033[1;93m",       # Bold yellow
        exploit="\033[91m",
        scanner="\033[93m",
        auxiliary="\033[95m",
        dos="\033[91m"
    ),
    
    "purple": Theme(
        name="purple",
        description="Royal purple and magenta",
        primary="\033[95m",        # Magenta
        secondary="\033[94m",      # Blue
        accent="\033[97m",         # White
        success="\033[92m",        # Green
        error="\033[91m",          # Red
        warning="\033[93m",        # Yellow
        info="\033[95m",           # Magenta
        text="\033[97m",           # White
        text_dim="\033[90m",       # Grey
        prompt="\033[95m",         # Magenta
        prompt_arrow="\033[97m",   # White
        border="\033[95m",         # Magenta
        header="\033[1;95m",       # Bold magenta
        exploit="\033[91m",
        scanner="\033[94m",
        auxiliary="\033[95m",
        dos="\033[93m"
    ),
    
    "minimal": Theme(
        name="minimal",
        description="Clean minimal theme with subtle colors",
        primary="\033[97m",        # White
        secondary="\033[90m",      # Grey
        accent="\033[96m",         # Cyan
        success="\033[92m",        # Green
        error="\033[91m",          # Red
        warning="\033[93m",        # Yellow
        info="\033[90m",           # Grey
        text="\033[97m",           # White
        text_dim="\033[90m",       # Grey
        prompt="\033[97m",         # White
        prompt_arrow="\033[90m",   # Grey
        border="\033[90m",         # Grey
        header="\033[1;97m",       # Bold white
        exploit="\033[91m",
        scanner="\033[97m",
        auxiliary="\033[90m",
        dos="\033[93m"
    ),
    
    "neon": Theme(
        name="neon",
        description="Bright neon cyberpunk style",
        primary="\033[96m",        # Cyan
        secondary="\033[95m",      # Magenta
        accent="\033[93m",         # Yellow
        success="\033[92m",        # Green
        error="\033[91m",          # Red
        warning="\033[93m",        # Yellow
        info="\033[96m",           # Cyan
        text="\033[97m",           # White
        text_dim="\033[95m",       # Magenta
        prompt="\033[95m",         # Magenta
        prompt_arrow="\033[96m",   # Cyan
        border="\033[96m",         # Cyan
        header="\033[1;93m",       # Bold yellow
        exploit="\033[91m",
        scanner="\033[96m",
        auxiliary="\033[95m",
        dos="\033[93m"
    ),
    
    "mono": Theme(
        name="mono",
        description="Monochrome - no colors",
        primary="",
        secondary="",
        accent="",
        success="",
        error="",
        warning="",
        info="",
        text="",
        text_dim="",
        text_bold="\033[1m",
        prompt="",
        prompt_arrow="",
        border="",
        header="\033[1m",
        exploit="",
        scanner="",
        auxiliary="",
        dos="",
        reset="\033[0m"
    )
}


class ThemeManager:
    """
    Manages color themes for BlueSploit.
    
    Features:
    - Built-in themes
    - Custom theme loading/saving
    - Theme switching
    - Color preview
    """
    
    def __init__(self, config_dir: str = None):
        self.config_dir = config_dir or os.path.expanduser("~/.bluesploit")
        self.themes_file = os.path.join(self.config_dir, "themes.json")
        self.config_file = os.path.join(self.config_dir, "config.json")
        
        self.themes = THEMES.copy()
        self.current_theme: Theme = THEMES["default"]
        
        self._ensure_config_dir()
        self._load_custom_themes()
        self._load_config()
    
    def _ensure_config_dir(self) -> None:
        """Ensure config directory exists"""
        try:
            os.makedirs(self.config_dir, exist_ok=True)
        except:
            pass
    
    def _load_custom_themes(self) -> None:
        """Load custom themes from file"""
        try:
            if os.path.exists(self.themes_file):
                with open(self.themes_file, 'r') as f:
                    custom = json.load(f)
                    for name, data in custom.items():
                        self.themes[name] = Theme(**data)
        except:
            pass
    
    def _load_config(self) -> None:
        """Load config including selected theme"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    theme_name = config.get("theme", "default")
                    if theme_name in self.themes:
                        self.current_theme = self.themes[theme_name]
        except:
            pass
    
    def _save_config(self) -> None:
        """Save config"""
        try:
            config = {"theme": self.current_theme.name}
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except:
            pass
    
    def get_theme(self, name: str = None) -> Theme:
        """Get theme by name or current theme"""
        if name:
            return self.themes.get(name, self.current_theme)
        return self.current_theme
    
    def set_theme(self, name: str) -> bool:
        """Set current theme"""
        if name in self.themes:
            self.current_theme = self.themes[name]
            self._save_config()
            return True
        return False
    
    def list_themes(self) -> Dict[str, str]:
        """List all available themes"""
        return {name: theme.description for name, theme in self.themes.items()}
    
    def save_custom_theme(self, theme: Theme) -> None:
        """Save a custom theme"""
        self.themes[theme.name] = theme
        
        # Save to file
        try:
            custom = {}
            if os.path.exists(self.themes_file):
                with open(self.themes_file, 'r') as f:
                    custom = json.load(f)
            
            custom[theme.name] = asdict(theme)
            
            with open(self.themes_file, 'w') as f:
                json.dump(custom, f, indent=2)
        except:
            pass
    
    def preview_theme(self, name: str) -> str:
        """Generate theme preview"""
        theme = self.themes.get(name)
        if not theme:
            return "Theme not found"
        
        preview = f"""
{theme.border}╔{'═'*50}╗{theme.reset}
{theme.border}║{theme.reset} {theme.header}Theme: {name}{theme.reset}
{theme.border}║{theme.reset} {theme.text_dim}{theme.description}{theme.reset}
{theme.border}╠{'═'*50}╣{theme.reset}
{theme.border}║{theme.reset} {theme.primary}Primary Color{theme.reset}
{theme.border}║{theme.reset} {theme.secondary}Secondary Color{theme.reset}
{theme.border}║{theme.reset} {theme.accent}Accent Color{theme.reset}
{theme.border}╠{'═'*50}╣{theme.reset}
{theme.border}║{theme.reset} {theme.success}✓ Success message{theme.reset}
{theme.border}║{theme.reset} {theme.error}✗ Error message{theme.reset}
{theme.border}║{theme.reset} {theme.warning}⚠ Warning message{theme.reset}
{theme.border}║{theme.reset} {theme.info}ℹ Info message{theme.reset}
{theme.border}╠{'═'*50}╣{theme.reset}
{theme.border}║{theme.reset} {theme.exploit}[exploit]{theme.reset} {theme.scanner}[scanner]{theme.reset} {theme.auxiliary}[aux]{theme.reset} {theme.dos}[dos]{theme.reset}
{theme.border}╚{'═'*50}╝{theme.reset}

{theme.prompt}bluesploit{theme.reset} {theme.prompt_arrow}>{theme.reset} sample command
"""
        return preview


# Global theme manager instance
theme_manager = ThemeManager()


def get_theme() -> Theme:
    """Get current theme"""
    return theme_manager.get_theme()


def set_theme(name: str) -> bool:
    """Set current theme"""
    return theme_manager.set_theme(name)


# Convenience color functions using current theme
def primary(text: str) -> str:
    t = get_theme()
    return f"{t.primary}{text}{t.reset}"

def secondary(text: str) -> str:
    t = get_theme()
    return f"{t.secondary}{text}{t.reset}"

def accent(text: str) -> str:
    t = get_theme()
    return f"{t.accent}{text}{t.reset}"

def success(text: str) -> str:
    t = get_theme()
    return f"{t.success}{text}{t.reset}"

def error(text: str) -> str:
    t = get_theme()
    return f"{t.error}{text}{t.reset}"

def warning(text: str) -> str:
    t = get_theme()
    return f"{t.warning}{text}{t.reset}"

def info(text: str) -> str:
    t = get_theme()
    return f"{t.info}{text}{t.reset}"

def bold(text: str) -> str:
    t = get_theme()
    return f"{t.text_bold}{text}{t.reset}"

def dim(text: str) -> str:
    t = get_theme()
    return f"{t.text_dim}{text}{t.reset}"
