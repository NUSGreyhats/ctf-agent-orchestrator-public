"""Plugin discovery and registry for CTF platform integrations."""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import CTFPlatformPlugin

_plugins: dict[str, CTFPlatformPlugin] = {}


def discover_plugins() -> None:
    """Scan the plugins package for CTFPlatformPlugin subclasses."""
    from .base import CTFPlatformPlugin

    package_dir = Path(__file__).parent
    for info in pkgutil.iter_modules([str(package_dir)]):
        if info.name == "base":
            continue
        try:
            module = importlib.import_module(f".{info.name}", __package__)
        except Exception:
            continue
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, CTFPlatformPlugin)
                and attr is not CTFPlatformPlugin
            ):
                try:
                    instance = attr()
                    _plugins[instance.name] = instance
                except Exception:
                    continue


def get_plugins() -> dict[str, CTFPlatformPlugin]:
    if not _plugins:
        discover_plugins()
    return _plugins


def get_plugin(name: str) -> CTFPlatformPlugin | None:
    return get_plugins().get(name)
