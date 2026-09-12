#!/usr/bin/env python3
"""AEGIS NIDS Control Plane CLI (aegisctl) v6.0

Modular CLI for managing the AEGIS NIDS service.
Each command is a separate module in tools/aegisctl/commands/.

Usage:
    python tools/aegisctl.py status
    python tools/aegisctl.py rules list
    python tools/aegisctl.py alerts view
    python tools/aegisctl.py dashboard
"""
from __future__ import annotations

import argparse
import importlib
import pkgutil
import sys
from pathlib import Path
from typing import Dict, Callable

# Ensure tools/ is on the path
TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def discover_commands() -> Dict[str, object]:
    """Import all command modules and return them."""
    commands = {}
    package = importlib.import_module("aegisctl.commands")
    for importer, modname, ispkg in pkgutil.iter_modules(package.__path__):
        if modname.startswith("_"):
            continue
        mod = importlib.import_module(f"aegisctl.commands.{modname}")
        commands[modname] = mod
    return commands


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AEGIS NIDS control plane CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd")

    # Discover and register all command modules
    commands = discover_commands()
    for name, mod in sorted(commands.items()):
        if hasattr(mod, "setup_subcommands"):
            mod.setup_subcommands(sub)

    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        return 2

    # Dispatch to the appropriate command module
    for name, mod in sorted(commands.items()):
        # Check for direct command match (e.g., cmd_status for "status")
        func_name = f"cmd_{args.cmd}"
        if hasattr(mod, func_name):
            return getattr(mod, func_name)(args)

        # Check for nested command match (e.g., cmd_rules_list for "rules" + "list")
        sub_attr = f"{args.cmd}_cmd"
        if hasattr(args, sub_attr) and getattr(args, sub_attr):
            sub_cmd = getattr(args, sub_attr)
            func_name = f"cmd_{args.cmd}_{sub_cmd}"
            if hasattr(mod, func_name):
                return getattr(mod, func_name)(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
