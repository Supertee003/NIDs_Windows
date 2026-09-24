"""Auto-discovers and registers all command modules."""
from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, Callable, Any
import argparse


COMMANDS: Dict[str, Callable] = {}


def register(name: str, func: Callable) -> None:
    COMMANDS[name] = func


def _discover() -> None:
    package = importlib.import_module(__package__)
    for _, name, _ in pkgutil.iter_modules(package.__path__):
        if name.startswith("_"):
            continue
        mod = importlib.import_module(f"{__package__}.{name}")
        if hasattr(mod, "register_commands"):
            mod.register_commands()


def get_commands() -> Dict[str, Callable]:
    if not COMMANDS:
        _discover()
    return COMMANDS


def setup_parser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="cmd")
    get_commands()
    for name, setup_fn in COMMANDS.items():
        if hasattr(setup_fn, "_subparser"):
            setup_fn._subparser(sub)
    return sub
