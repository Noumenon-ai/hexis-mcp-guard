"""Check registry with auto-discovery of all check modules."""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hexis.checks.base import BaseCheck


class CheckRegistry:
    """Auto-discovers and manages all security checks."""

    def __init__(self) -> None:
        self._checks: list[BaseCheck] = []

    def register(self, check: BaseCheck) -> None:
        self._checks.append(check)

    @property
    def checks(self) -> list[BaseCheck]:
        return list(self._checks)

    def get_by_category(self, category: str) -> list[BaseCheck]:
        return [c for c in self._checks if c.category == category]

    def get_by_id(self, rule_id: str) -> BaseCheck | None:
        for c in self._checks:
            if c.rule_id == rule_id:
                return c
        return None

    def auto_discover(self) -> None:
        """Import all check modules in this package to trigger registration."""
        import hexis.checks as checks_pkg

        for _importer, modname, _ispkg in pkgutil.iter_modules(checks_pkg.__path__):
            if modname not in ("base", "__init__"):
                importlib.import_module(f"hexis.checks.{modname}")


# Global registry instance
registry = CheckRegistry()


def get_registry() -> CheckRegistry:
    """Get the global registry, auto-discovering checks on first call."""
    if not registry.checks:
        registry.auto_discover()
    return registry
