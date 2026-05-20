"""
Sondar banner and display helpers.

Keeps operator-facing terminal output consistent across Sondar workflows.
The stylised sOndar logo is used only on the main menu header. Workflow
screens use clean text headers without repeating the logo.
"""


# ------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------

HEADER_WIDTH = 60

SONDAR_LOGO = [
    "            /██████                  /██",
    "           /██__  ██                | ██",
    "  /███████| ██  \\ ██ /███████   /███████  /██████   /██████",
    " /██_____/| ██  | ██| ██__  ██ /██__  ██ |____  ██ /██__  ██",
    "|  ██████ | ██  | ██| ██  \\ ██| ██  | ██  /███████| ██  \\__/",
    " \\____  ██| ██  | ██| ██  | ██| ██  | ██ /██__  ██| ██",
    " /███████/|  ██████/| ██  | ██|  ███████|  ███████| ██",
    "|_______/  \\______/ |__/  |__/ \\_______/ \\_______/|__/",
]


# ------------------------------------------------------------
# LOGO HELPERS
# ------------------------------------------------------------

def print_logo() -> None:
    """Print the stylised sOndar ASCII logo."""
    for line in SONDAR_LOGO:
        print(line)


# ------------------------------------------------------------
# HEADER HELPERS
# ------------------------------------------------------------

def print_menu_header() -> None:
    """
    Print the main menu header.

    The logo is intentionally printed only here so repeated workflow screens
    stay clean and do not flood the terminal.
    """
    print()
    print_logo()
    print()
    print("Home Network Scan Monitor")
    print("=" * HEADER_WIDTH)
    print()


def print_workflow_header(title: str) -> None:
    """
    Print a workflow header without the ASCII logo.

    Used for Network Scan and Clear Artefacts screens after the operator has
    selected a menu action.
    """
    print()
    print(title)
    print("=" * HEADER_WIDTH)
    print()


def print_section(title: str) -> None:
    """Print a smaller workflow section header."""
    print(f"--- {title} ---")


# ------------------------------------------------------------
# STATUS HELPERS
# ------------------------------------------------------------

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