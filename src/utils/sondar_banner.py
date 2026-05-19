"""
Sondar banner and display helpers.

Keeps operator-facing terminal output consistent across Sondar workflows.
"""


# ------------------------------------------------------------
# DISPLAY HELPERS
# ------------------------------------------------------------

def print_logo() -> None:
    """Print the Sondar ASCII logo."""
    print(" ___  ___  _  _  ___   _   ___ ")
    print("/ __|/ _ \\| \\| ||   \\ /_\\ | _ \\")
    print("\\__ \\ (_) | .` || |) / _ \\|   /")
    print("|___/\\___/|_|\\_||___/_/ \\_\\_|_\\")


def print_main_header(title: str) -> None:
    """Print a main Sondar workflow header."""
    print()
    print_logo()
    print()
    print("Home Network Scan Monitor")
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