"""Pytest config for tests housed under scripts/.

Adds the repo root to sys.path so tests can `from core...` and
`from modules...` exactly the same way the runtime does.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
