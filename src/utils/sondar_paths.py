"""
Sondar path utilities.

Centralises project path resolution so the rest of the tool does not rely on
hardcoded working-directory assumptions.
"""

from pathlib import Path


# ------------------------------------------------------------
# PATHS
# ------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT_DIR / "config"
DATA_DIR = ROOT_DIR / "data"

CONFIG_PATH = CONFIG_DIR / "sondar_config.json"
SCANS_DIR = DATA_DIR / "scans"
REPORTS_DIR = DATA_DIR / "reports"
LOGS_DIR = DATA_DIR / "logs"


# ------------------------------------------------------------
# DISPLAY HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """
    Return a repository-relative path for clean terminal output.

    If the path cannot be made relative to the repository root, return the
    original path as a string.
    """
    try:
        return path.relative_to(ROOT_DIR).as_posix()
    except ValueError:
        return str(path)


# ------------------------------------------------------------
# DIRECTORY HELPERS
# ------------------------------------------------------------

def ensure_directory(path: Path) -> None:
    """Create a directory if it does not already exist."""
    path.mkdir(parents=True, exist_ok=True)


def prepare_data_directories() -> None:
    """
    Ensure Sondar data directories exist.
    """
    for directory in (DATA_DIR, SCANS_DIR, REPORTS_DIR, LOGS_DIR):
        ensure_directory(directory)


def get_required_paths() -> dict[str, Path]:
    """
    Return the core Sondar paths used during pre-flight checks.
    """
    return {
        "root_dir": ROOT_DIR,
        "config_path": CONFIG_PATH,
        "data_dir": DATA_DIR,
        "scans_dir": SCANS_DIR,
        "reports_dir": REPORTS_DIR,
        "logs_dir": LOGS_DIR,
    }