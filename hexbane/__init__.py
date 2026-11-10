"""Hexbane: check AI agent skills, MCP servers and tools before you load them, and guard them while they run."""

from .scanner import RULES, scan_files, scan_path, scan_paths, scan_text  # noqa: F401

__version__ = RULES["version"]
