"""
BlueSploit UI Package
User interface components for BlueSploit

Components:
- completion: Tab completion and command history
- themes: Color themes and customization
- progress: Progress bars and spinners
- dashboard: TUI dashboard (curses-based)
- webui: Web-based interface (Flask)
"""

from .completion import (
    TabCompleter,
    CommandHistory,
    completer,
    history,
    setup_completion,
    save_history
)

from .themes import (
    Theme,
    ThemeManager,
    theme_manager,
    get_theme,
    primary,
    secondary,
    accent,
    success,
    error,
    warning,
    info,
    bold,
    dim
)

from .progress import (
    ProgressBar,
    Spinner,
    MultiProgress,
    StatusLine,
    progress_bar,
    spinner,
    status_line,
    STYLES as PROGRESS_STYLES
)

__all__ = [
    # Completion
    'TabCompleter',
    'CommandHistory', 
    'completer',
    'history',
    'setup_completion',
    'save_history',
    
    # Themes
    'Theme',
    'ThemeManager',
    'theme_manager',
    'get_theme',
    'primary',
    'secondary',
    'accent',
    'success',
    'error',
    'warning',
    'info',
    'bold',
    'dim',
    
    # Progress
    'ProgressBar',
    'Spinner',
    'MultiProgress',
    'StatusLine',
    'progress_bar',
    'spinner',
    'status_line',
    'PROGRESS_STYLES',
]

# Lazy imports for optional components
def get_dashboard():
    """Get TUI dashboard (requires curses)"""
    from .dashboard import Dashboard
    return Dashboard

def get_webui():
    """Get Web UI (requires Flask)"""
    from .webui import WebUI
    return WebUI
