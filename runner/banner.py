"""Startup banner: pre-rendered ASCII + Braille logo, colorized."""
from pathlib import Path

from runner import utils


def render() -> str:
    """Return the colorized startup banner, or a literal fallback if missing.

    - every `#` glyph -> bright cyan ("96")
    - lines with no `#` and no Braille char (U+2800–U+28FF) -> dim ("2")
    - Braille logo lines -> left as-is
    """
    asset = Path(__file__).resolve().parent.parent / "assets" / "startup_banner.txt"
    try:
        text = asset.read_text()
    except (OSError, FileNotFoundError):
        return "BuntyRun by Strasser Lab"

    lines = []
    for line in text.splitlines():
        if "#" in line:
            lines.append("".join(utils.colorize(ch, "91") if ch == "#" else ch for ch in line))
        elif any("\u2800" <= ch <= "\u28ff" for ch in line):
            lines.append(line)
        else:
            lines.append(utils.colorize(line, "2"))
    return "\n".join(lines)


def print_banner() -> None:
    print(render())
