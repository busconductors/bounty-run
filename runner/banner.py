"""Startup banner: Braille face + figlet-`small` wordmark/credit, in red."""
from pathlib import Path

from runner import utils


def render() -> str:
    """Return the colorized startup banner, or a literal fallback if missing.

    Everything renders bright red ("91"): the Braille face, the figlet-`small`
    wordmark and the "by Strasser Lab" credit. The plain-prose tagline is
    dimmed red ("2;91") so it sits behind the art. Blank lines stay blank.
    """
    asset = Path(__file__).resolve().parent.parent / "assets" / "startup_banner.txt"
    try:
        text = asset.read_text()
    except (OSError, FileNotFoundError):
        return "BuntyRun by Strasser Lab"

    lines = []
    for line in text.splitlines():
        if not line.strip():
            lines.append("")
        elif line.strip().startswith("recon orchestrator"):
            lines.append(utils.colorize(line, "2;91"))
        else:
            lines.append(utils.colorize(line, "91"))
    return "\n".join(lines)


def print_banner() -> None:
    print(render())
