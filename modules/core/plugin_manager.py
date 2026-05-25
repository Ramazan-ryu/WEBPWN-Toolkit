import os
import importlib
import inspect
from pathlib import Path
from typing import Dict, Type

try:
    from modules.core.base_scanner import BaseScanner
except ImportError:
    BaseScanner = object


class PluginManager:
    """
    Discovers and loads all WebPwn scanner modules dynamically.
    Instead of hardcoding each module in main.py, this scans the directories
    and registers any class that ends with 'Scanner', 'Tester', or 'Enumerator',
    or inherits from BaseScanner.
    """

    def __init__(self):
        self.web_modules: Dict[str, Type] = {}
        self.recon_modules: Dict[str, Type] = {}
        self.mobile_modules: Dict[str, Type] = {}

        self._root = Path(__file__).parent.parent
        self._discover_all()

    def _discover_in_dir(self, directory: str) -> Dict[str, Type]:
        modules = {}
        dir_path = self._root / directory
        if not dir_path.exists():
            return modules

        for py_file in dir_path.glob("*.py"):
            if py_file.name.startswith("__"):
                continue

            mod_name = f"modules.{directory}.{py_file.stem}"
            try:
                mod = importlib.import_module(mod_name)
                # Find the main scanner class in the module
                for name, obj in inspect.getmembers(mod, inspect.isclass):
                    # Exclude the base class itself and imported classes from other modules
                    if obj.__module__ == mod_name:
                        if (
                            name.endswith("Scanner")
                            or name.endswith("Tester")
                            or name.endswith("Enumerator")
                            or name.endswith("Exploiter")
                            or name.endswith("AbuseTester")
                            or name.endswith("HTTPSmuggling")
                        ):
                            modules[py_file.stem] = obj
            except Exception as e:
                # Silently ignore broken modules during discovery, or log them
                pass
        return modules

    def _discover_all(self):
        self.web_modules = self._discover_in_dir("web")
        self.recon_modules = self._discover_in_dir("recon")
        self.mobile_modules = self._discover_in_dir("mobile")

    def get_all_web_modules(self):
        return self.web_modules

    def get_all_recon_modules(self):
        return self.recon_modules

    def get_all_mobile_modules(self):
        return self.mobile_modules


plugin_manager = PluginManager()
