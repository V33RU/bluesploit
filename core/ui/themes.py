"""
BlueSploit UI: Themes System

Author: v33ru
"""

from dataclasses import dataclass


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


DEFAULT_THEME = Theme(
    name="default",
    description="Default BlueSploit theme (cyan/red)"
)


class ThemeManager:
    """Manages color theme for BlueSploit."""

    def __init__(self):
        self.current_theme: Theme = DEFAULT_THEME

    def get_theme(self) -> Theme:
        """Get current theme"""
        return self.current_theme


# Global theme manager instance
theme_manager = ThemeManager()


def get_theme() -> Theme:
    """Get current theme"""
    return theme_manager.get_theme()


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
