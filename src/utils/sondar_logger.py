"""
Sondar logging utilities.

Creates a consistent runtime logger for Sondar workflows. The logger writes
timestamped log files under data/logs while keeping terminal output controlled
by the main workflow.
"""

import logging
from datetime import datetime
from pathlib import Path

from utils.sondar_paths import LOGS_DIR, relative_path


# ------------------------------------------------------------
# LOGGER SETUP
# ------------------------------------------------------------

def setup_logger() -> tuple[logging.Logger, Path]:
    """
    Configure and return the Sondar logger and log path.

    A timestamped log file is created for each run.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOGS_DIR / f"sondar_{timestamp}.log"

    logger = logging.getLogger("sondar")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    logger.info("Sondar logger initialised")
    logger.info("Log file: %s", relative_path(log_path))

    return logger, log_path