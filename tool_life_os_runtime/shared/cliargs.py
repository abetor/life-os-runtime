"""ArgumentParser with the repository exit-code contract: usage errors exit 1.

Standard argparse terminates invalid argument parsing with ``sys.exit(2)``, but
this CLI contract defines ``EXIT_FAIL=1`` and has no meaning for code 2. The
subclass changes only the exit code; usage text and stderr messages are kept.
Subparsers inherit the class automatically because ``add_subparsers`` uses
``parser_class = type(parent)``, so subcommand errors also exit 1.

Vendored from the tool template. This repository owns its copy.
"""
from __future__ import annotations

import argparse
import sys


class ArgumentParser(argparse.ArgumentParser):
    """Behave like argparse.ArgumentParser, but exit 1 on usage errors."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")
