"""
BlueSploit UI: Progress Bars
Visual progress indicators for long-running operations

Author: v33ru
"""

import sys
import time
import threading
from typing import Optional, Callable, List
from dataclasses import dataclass


@dataclass
class ProgressStyle:
    """Progress bar style configuration"""
    bar_char: str = "█"
    empty_char: str = "░"
    left_bracket: str = "["
    right_bracket: str = "]"
    spinner_chars: str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    
    # Colors (ANSI)
    bar_color: str = "\033[92m"      # Green
    empty_color: str = "\033[90m"    # Grey
    text_color: str = "\033[97m"     # White
    percent_color: str = "\033[96m"  # Cyan
    speed_color: str = "\033[93m"    # Yellow
    reset: str = "\033[0m"


# Pre-defined styles
STYLES = {
    "default": ProgressStyle(),
    
    "classic": ProgressStyle(
        bar_char="=",
        empty_char="-",
        left_bracket="[",
        right_bracket="]"
    ),
    
    "blocks": ProgressStyle(
        bar_char="▓",
        empty_char="░"
    ),
    
    "arrows": ProgressStyle(
        bar_char="►",
        empty_char="─"
    ),
    
    "dots": ProgressStyle(
        bar_char="●",
        empty_char="○"
    ),
    
    "minimal": ProgressStyle(
        bar_char="─",
        empty_char=" ",
        left_bracket="",
        right_bracket=""
    ),
    
    "fancy": ProgressStyle(
        bar_char="▰",
        empty_char="▱",
        spinner_chars="◐◓◑◒"
    )
}


class ProgressBar:
    """
    Visual progress bar for terminal output.
    
    Features:
    - Percentage display
    - ETA calculation
    - Speed calculation
    - Multiple styles
    - Thread-safe updates
    """
    
    def __init__(self, total: int, width: int = 40, 
                 style: str = "default", desc: str = "",
                 show_eta: bool = True, show_speed: bool = True):
        self.total = total
        self.current = 0
        self.width = width
        self.style = STYLES.get(style, STYLES["default"])
        self.desc = desc
        self.show_eta = show_eta
        self.show_speed = show_speed
        
        self.start_time = time.time()
        self.last_update = self.start_time
        self.last_current = 0
        
        self._lock = threading.Lock()
        self._finished = False
    
    def update(self, n: int = 1) -> None:
        """Update progress by n steps"""
        with self._lock:
            self.current = min(self.current + n, self.total)
            self._render()
    
    def set(self, value: int) -> None:
        """Set progress to specific value"""
        with self._lock:
            self.current = min(value, self.total)
            self._render()
    
    def _calculate_speed(self) -> float:
        """Calculate items per second"""
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            return self.current / elapsed
        return 0
    
    def _calculate_eta(self) -> str:
        """Calculate estimated time remaining"""
        if self.current == 0:
            return "?"
        
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed
        
        if rate > 0:
            remaining = (self.total - self.current) / rate
            
            if remaining < 60:
                return f"{remaining:.0f}s"
            elif remaining < 3600:
                return f"{remaining/60:.1f}m"
            else:
                return f"{remaining/3600:.1f}h"
        
        return "?"
    
    def _render(self) -> None:
        """Render progress bar to terminal"""
        s = self.style
        
        # Calculate percentage
        percent = (self.current / self.total * 100) if self.total > 0 else 0
        
        # Calculate filled width
        filled = int(self.width * self.current / self.total) if self.total > 0 else 0
        empty = self.width - filled
        
        # Build bar
        bar = (f"{s.bar_color}{s.bar_char * filled}{s.reset}"
               f"{s.empty_color}{s.empty_char * empty}{s.reset}")
        
        # Build line
        line = f"\r  {s.text_color}{self.desc}{s.reset} " if self.desc else "\r  "
        line += f"{s.left_bracket}{bar}{s.right_bracket}"
        line += f" {s.percent_color}{percent:5.1f}%{s.reset}"
        line += f" ({self.current}/{self.total})"
        
        # Add speed
        if self.show_speed:
            speed = self._calculate_speed()
            line += f" {s.speed_color}{speed:.1f}/s{s.reset}"
        
        # Add ETA
        if self.show_eta and self.current < self.total:
            eta = self._calculate_eta()
            line += f" ETA: {eta}"
        
        # Print with padding to clear previous line
        sys.stdout.write(f"{line:<100}")
        sys.stdout.flush()
    
    def finish(self, message: str = None) -> None:
        """Complete the progress bar"""
        with self._lock:
            self.current = self.total
            self._render()
            self._finished = True
        
        if message:
            print(f"\n  {self.style.bar_color}✓{self.style.reset} {message}")
        else:
            print()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        if not self._finished:
            self.finish()


class Spinner:
    """
    Animated spinner for indeterminate operations.
    
    Features:
    - Multiple animation styles
    - Custom message
    - Async-friendly
    """
    
    def __init__(self, message: str = "Processing...", 
                 style: str = "default"):
        self.message = message
        self.style = STYLES.get(style, STYLES["default"])
        self.chars = self.style.spinner_chars
        
        self._running = False
        self._thread = None
        self._frame = 0
    
    def _animate(self) -> None:
        """Animation loop"""
        while self._running:
            char = self.chars[self._frame % len(self.chars)]
            sys.stdout.write(f"\r  {self.style.bar_color}{char}{self.style.reset} {self.message}")
            sys.stdout.flush()
            self._frame += 1
            time.sleep(0.1)
    
    def start(self) -> None:
        """Start spinner"""
        self._running = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
    
    def stop(self, success: bool = True, message: str = None) -> None:
        """Stop spinner"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)
        
        # Clear line and print result
        final_msg = message or self.message
        if success:
            sys.stdout.write(f"\r  {self.style.bar_color}✓{self.style.reset} {final_msg}    \n")
        else:
            sys.stdout.write(f"\r  \033[91m✗\033[0m {final_msg}    \n")
        sys.stdout.flush()
    
    def update(self, message: str) -> None:
        """Update spinner message"""
        self.message = message
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, *args):
        self.stop(success=(exc_type is None))


class MultiProgress:
    """
    Multiple progress bars for parallel operations.
    
    Features:
    - Track multiple tasks
    - Independent progress for each
    - Clean terminal output
    """
    
    def __init__(self):
        self.bars: List[ProgressBar] = []
        self._lock = threading.Lock()
    
    def add_task(self, total: int, desc: str = "") -> int:
        """Add a new task and return its index"""
        with self._lock:
            bar = ProgressBar(total, desc=desc, show_eta=False, show_speed=False)
            self.bars.append(bar)
            return len(self.bars) - 1
    
    def update(self, task_id: int, n: int = 1) -> None:
        """Update a specific task"""
        with self._lock:
            if 0 <= task_id < len(self.bars):
                self.bars[task_id].update(n)
                self._render_all()
    
    def _render_all(self) -> None:
        """Render all progress bars"""
        # Move cursor up
        if len(self.bars) > 1:
            sys.stdout.write(f"\033[{len(self.bars)-1}A")
        
        for bar in self.bars:
            bar._render()
            print()
    
    def finish(self) -> None:
        """Finish all tasks"""
        for bar in self.bars:
            bar.finish()


class StatusLine:
    """
    Single-line status indicator that updates in place.
    
    Features:
    - Status icon (✓, ✗, ⚠, ℹ)
    - Timed updates
    - Color coding
    """
    
    ICONS = {
        "success": ("\033[92m", "✓"),
        "error": ("\033[91m", "✗"),
        "warning": ("\033[93m", "⚠"),
        "info": ("\033[94m", "ℹ"),
        "working": ("\033[96m", "◌"),
    }
    
    def __init__(self, initial_message: str = ""):
        self.message = initial_message
        self.status = "working"
    
    def update(self, message: str, status: str = "working") -> None:
        """Update status line"""
        self.message = message
        self.status = status
        
        color, icon = self.ICONS.get(status, self.ICONS["info"])
        sys.stdout.write(f"\r  {color}{icon}\033[0m {message:<70}")
        sys.stdout.flush()
    
    def success(self, message: str) -> None:
        """Show success status"""
        self.update(message, "success")
        print()
    
    def error(self, message: str) -> None:
        """Show error status"""
        self.update(message, "error")
        print()
    
    def warning(self, message: str) -> None:
        """Show warning status"""
        self.update(message, "warning")
        print()
    
    def info(self, message: str) -> None:
        """Show info status"""
        self.update(message, "info")
        print()


# Convenience functions
def progress_bar(total: int, **kwargs) -> ProgressBar:
    """Create a progress bar"""
    return ProgressBar(total, **kwargs)


def spinner(message: str = "Processing...", **kwargs) -> Spinner:
    """Create a spinner"""
    return Spinner(message, **kwargs)


def status_line(message: str = "") -> StatusLine:
    """Create a status line"""
    return StatusLine(message)


# Demo function
def demo():
    """Demonstrate progress bar features"""
    print("\n  === Progress Bar Demo ===\n")
    
    # Basic progress bar
    print("  Basic progress bar:")
    with ProgressBar(100, desc="Scanning") as bar:
        for i in range(100):
            time.sleep(0.02)
            bar.update(1)
    
    # Different styles
    print("\n  Different styles:")
    for style_name in ["classic", "blocks", "arrows", "dots", "fancy"]:
        with ProgressBar(50, desc=f"{style_name:10}", style=style_name, 
                        show_eta=False, show_speed=False, width=30) as bar:
            for i in range(50):
                time.sleep(0.01)
                bar.update(1)
    
    # Spinner
    print("\n  Spinner:")
    with Spinner("Connecting to device...") as spin:
        time.sleep(2)
    
    # Status line
    print("\n  Status updates:")
    status = StatusLine()
    status.update("Initializing...", "working")
    time.sleep(0.5)
    status.update("Connecting...", "working")
    time.sleep(0.5)
    status.update("Scanning services...", "working")
    time.sleep(0.5)
    status.success("Completed successfully!")
    
    print("\n  === Demo Complete ===\n")


if __name__ == "__main__":
    demo()
