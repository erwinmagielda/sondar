"""
Sondar banner and display helpers.

Keeps operator-facing terminal output consistent across Sondar workflows.
"""


# ------------------------------------------------------------
# DISPLAY HELPERS
# ------------------------------------------------------------

def print_main_header(title: str) -> None:
    """Print a main Sondar workflow header."""
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)
    print()


def print_section(title: str) -> None:
    """Print a smaller workflow section header."""
    print(f"--- {title} ---")


def print_status(marker: str, message: str) -> None:
    """
    Print a formatted status message.

    Expected markers:
        * active step
        + success
        i information
        ! warning
        X error
    """
    print(f"[{marker}] {message}")