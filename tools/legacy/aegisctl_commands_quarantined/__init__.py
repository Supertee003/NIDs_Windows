"""Auto-discovers and registers all command modules."""
from __future__ import annotations

# QUARANTINED (LEGACY-INERT-001): retained for history only.
# Nothing in the runtime imports this file and the installer does not ship it.
# Several of these scripts rewrite tracked files when run (for example
# tools/aegisctl/commands/console.py or AUTHORITY_MAP.json), so an accidental
# `python tools/legacy/<name>.py` was a tree mutation. The guard below makes the
# file inert: it exits before any line of the original body executes.
raise SystemExit(
    "QUARANTINED: tools/legacy/aegisctl_commands_quarantined/__init__.py must not run; retained for history only."
)

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
