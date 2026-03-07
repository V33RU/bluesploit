"""
BlueSploit Module Loader
Dynamically loads and manages modules from the modules directory
"""

import os
import sys
import importlib.util
from pathlib import Path
from typing import Optional, List, Dict, Any
from core.base import BaseModule, ModuleType


class ModuleLoader:
    """
    Dynamically loads BlueSploit modules from the filesystem

    Scans the modules/ directory recursively, indexes all valid Python
    files, and provides dynamic loading via importlib. Each module file
    must export a class named 'Module' that inherits from BaseModule.
    """

    def __init__(self, modules_path: Optional[str] = None):
        """
        Initialize the module loader

        Args:
            modules_path: Path to modules directory (defaults to ./modules)
        """
        if modules_path is None:
            base_dir = Path(__file__).parent.parent
            self.modules_path = base_dir / "modules"
        else:
            self.modules_path = Path(modules_path)

        self._module_cache: Dict[str, BaseModule] = {}
        self._index: Dict[str, str] = {}  # module_path -> file_path
        self._build_index()

    def _build_index(self) -> None:
        """
        Build an index of all available modules
        Scans the modules directory recursively, skipping invalid files
        """
        self._index.clear()

        if not self.modules_path.exists():
            print(f"[\033[93m!\033[0m] Modules directory not found: {self.modules_path}")
            return

        for root, dirs, files in os.walk(self.modules_path):
            # Skip __pycache__ directories
            dirs[:] = [d for d in dirs if d != '__pycache__']

            for file in files:
                if file.endswith('.py') and not file.startswith('__'):
                    # Skip files with invalid Python identifiers (e.g., hyphens)
                    module_name = file[:-3]
                    if not module_name.isidentifier():
                        continue

                    file_path = Path(root) / file

                    # Build module path (e.g., scanners/ble/discovery)
                    rel_path = file_path.relative_to(self.modules_path)
                    module_path = str(rel_path.with_suffix('')).replace(os.sep, '/')

                    self._index[module_path] = str(file_path)

    def refresh(self) -> None:
        """Refresh the module index and clear cache"""
        self._module_cache.clear()
        self._build_index()

    def load(self, module_path: str) -> Optional[BaseModule]:
        """
        Load a module by its path

        Args:
            module_path: Module path (e.g., 'exploits/bluefrag')

        Returns:
            Loaded module instance or None if not found
        """
        # Normalize path
        module_path = module_path.strip().replace('\\', '/')

        # Check cache first
        if module_path in self._module_cache:
            return self._module_cache[module_path]

        # Find in index
        if module_path not in self._index:
            # Try partial match
            matches = [p for p in self._index.keys() if module_path in p]
            if len(matches) == 1:
                module_path = matches[0]
            elif len(matches) > 1:
                print(f"[\033[93m!\033[0m] Ambiguous module path. Matches:")
                for m in sorted(matches):
                    print(f"      {m}")
                return None
            else:
                print(f"[\033[91m!\033[0m] Module not found: {module_path}")
                return None

        file_path = self._index[module_path]

        try:
            # Load module dynamically
            spec = importlib.util.spec_from_file_location(
                f"bluesploit.modules.{module_path.replace('/', '.')}",
                file_path
            )

            if spec is None or spec.loader is None:
                print(f"[\033[91m!\033[0m] Failed to load module spec: {module_path}")
                return None

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            # Get the Module class from the loaded module
            if not hasattr(module, 'Module'):
                # Provide helpful hint about what classes exist
                candidates = [
                    n for n in dir(module)
                    if not n.startswith('_') and isinstance(getattr(module, n, None), type)
                    and issubclass(getattr(module, n), BaseModule)
                ]
                hint = f" (found BaseModule subclasses: {candidates})" if candidates else ""
                print(f"[\033[91m!\033[0m] No 'Module' class in: {module_path}{hint}")
                return None

            # Instantiate and cache
            instance = module.Module()
            self._module_cache[module_path] = instance

            return instance

        except Exception as e:
            print(f"[\033[91m!\033[0m] Error loading {module_path}: {e}")
            return None

    def search(self, query: str) -> List[str]:
        """
        Search for modules by path name

        Args:
            query: Search string (matched against module path)

        Returns:
            List of matching module paths
        """
        query = query.lower()
        return sorted(p for p in self._index.keys() if query in p.lower())

    def search_deep(self, query: str) -> List[str]:
        """
        Deep search across module paths, descriptions, and CVEs

        Args:
            query: Search string (matched against path, description, CVE)

        Returns:
            List of matching module paths
        """
        query_lower = query.lower()
        results = set()

        for module_path in self._index.keys():
            # Path match
            if query_lower in module_path.lower():
                results.add(module_path)
                continue

            # Load module and check description/CVE
            module = self.load(module_path)
            if module:
                # Description match
                if query_lower in module.info.description.lower():
                    results.add(module_path)
                    continue

                # CVE match
                if module.info.cve:
                    cve_list = module.info.cve if isinstance(module.info.cve, list) else [module.info.cve]
                    if any(query_lower in c.lower() for c in cve_list):
                        results.add(module_path)
                        continue

                # Author match
                if any(query_lower in a.lower() for a in module.info.author):
                    results.add(module_path)

        return sorted(results)

    def list_all(self) -> List[str]:
        """List all available module paths"""
        return sorted(self._index.keys())

    def list_by_type(self, module_type: ModuleType) -> List[str]:
        """
        List modules by type (matches directory prefix)

        Args:
            module_type: Type of modules to list

        Returns:
            List of module paths matching the type
        """
        type_prefix = module_type.value
        return sorted(p for p in self._index.keys() if p.startswith(type_prefix + '/') or p.startswith(type_prefix))

    def get_module_info(self, module_path: str) -> Optional[Dict[str, Any]]:
        """
        Get module metadata

        Args:
            module_path: Module path

        Returns:
            Dictionary with module info or None
        """
        module = self.load(module_path)
        if module is None:
            return None

        info = {
            "name": module.info.name,
            "description": module.info.description,
            "author": module.info.author,
            "protocol": module.info.protocol.value,
            "severity": module.info.severity.value,
            "type": module.module_type.value,
        }

        if module.info.cve:
            info["cve"] = module.info.cve

        return info

    @property
    def module_count(self) -> int:
        """Get total number of indexed modules"""
        return len(self._index)

    def stats(self) -> Dict[str, int]:
        """Get module count by category (directory prefix)"""
        stats = {}
        for module_type in ModuleType:
            count = len(self.list_by_type(module_type))
            if count > 0:
                stats[module_type.value] = count
        return stats
