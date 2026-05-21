"""
Sondar artefact management.

Provides helper functions for clearing generated runtime artefacts while
preserving repository structure files such as .gitkeep.
"""

import shutil
from pathlib import Path

from utils.sondar_paths import (
    INVENTORY_DIR,
    LOGS_DIR,
    REPORTS_DIR,
    ROOT_DIR,
    SCANS_DIR,
    relative_path,
)


# ------------------------------------------------------------
# ARTEFACT TARGETS
# ------------------------------------------------------------

ARTEFACT_DIRS = {
    "logs": LOGS_DIR,
    "scans": SCANS_DIR,
    "reports": REPORTS_DIR,
    "inventory": INVENTORY_DIR,
}

PRESERVED_FILES = {
    ".gitkeep",
}


# ------------------------------------------------------------
# DISPLAY HELPERS
# ------------------------------------------------------------

def get_clear_targets() -> list[str]:
    """
    Return human-facing artefact targets selected for cleanup.

    These values are displayed before deletion so the operator can review what
    will be affected.
    """
    targets = [
        relative_path(LOGS_DIR),
        relative_path(SCANS_DIR),
        relative_path(REPORTS_DIR),
        relative_path(INVENTORY_DIR),
        "Python cache artefacts",
    ]

    return targets


# ------------------------------------------------------------
# CLEAR HELPERS
# ------------------------------------------------------------

def should_preserve(path: Path) -> bool:
    """Return True if a file should not be removed."""
    return path.name in PRESERVED_FILES


def clear_directory(directory: Path) -> list[str]:
    """
    Remove generated files from a directory.

    Preserved files such as .gitkeep are left untouched.
    """
    removed_files = []

    if not directory.exists():
        return removed_files

    for path in directory.iterdir():
        if path.is_dir():
            continue

        if should_preserve(path):
            continue

        path.unlink()
        removed_files.append(relative_path(path))

    return removed_files


def clear_pycache_directories() -> list[str]:
    """
    Remove Python __pycache__ directories from the repository.
    """
    removed_directories = []

    for pycache_dir in ROOT_DIR.rglob("__pycache__"):
        if pycache_dir.is_dir():
            removed_directories.append(relative_path(pycache_dir))
            shutil.rmtree(pycache_dir)

    return removed_directories


def clear_runtime_artefacts() -> dict[str, list[str]]:
    """
    Clear generated Sondar runtime artefacts.

    Returns removed files and directories grouped by artefact type.
    """
    removed = {}

    for artefact_type, directory in ARTEFACT_DIRS.items():
        removed[artefact_type] = clear_directory(directory)

    removed["pycache"] = clear_pycache_directories()

    return removed


def count_removed_files(removed: dict[str, list[str]]) -> int:
    """Return the total number of removed artefact files/directories."""
    return sum(len(items) for items in removed.values())