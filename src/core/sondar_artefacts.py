"""
Sondar artefact management.

Provides helper functions for clearing generated runtime artefacts while
preserving repository structure files such as .gitkeep.
"""

from pathlib import Path

from utils.sondar_paths import (
    INVENTORY_DIR,
    LOGS_DIR,
    REPORTS_DIR,
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


def clear_runtime_artefacts() -> dict[str, list[str]]:
    """
    Clear generated Sondar runtime artefacts.

    Returns a dictionary containing removed files grouped by artefact type.
    """
    removed = {}

    for artefact_type, directory in ARTEFACT_DIRS.items():
        removed[artefact_type] = clear_directory(directory)

    return removed


def count_removed_files(removed: dict[str, list[str]]) -> int:
    """Return the total number of removed artefact files."""
    return sum(len(files) for files in removed.values())