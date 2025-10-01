"""Package resources related to ShieldGents branding."""

from __future__ import annotations

import sys
from functools import lru_cache
from importlib import resources
from typing import TextIO


@lru_cache(maxsize=1)
def get_logo_text() -> str:
    """Return the ShieldGents logo ASCII art."""
    try:
        return resources.read_text(__name__, "logo.txt", encoding="utf-8")
    except (FileNotFoundError, OSError):
        return "ShieldGents"


def print_logo(stream: TextIO | None = None) -> None:
    """Print the logo to the provided stream (stdout by default)."""
    output = stream or sys.stdout
    logo = get_logo_text()
    output.write(logo)
    if not logo.endswith("\n"):
        output.write("\n")
    output.flush()
