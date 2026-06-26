

from __future__ import annotations

from pathlib import Path

from . import header_analysis, language_analysis, link_analysis, parser, scoring
from .models import OverallResult, ParsedEmail

# The analysis modules, in report order. Each exposes ``analyze(ParsedEmail)``.
_ANALYZERS = (header_analysis, link_analysis, language_analysis)


def analyze_parsed(email: ParsedEmail) -> OverallResult:
    """Run every module on an already-parsed email and combine the results."""
    modules = [mod.analyze(email) for mod in _ANALYZERS]
    return scoring.combine(email, modules)


def analyze_bytes(raw: bytes, source: str = "") -> OverallResult:
    """Parse raw message bytes and return the overall verdict."""
    return analyze_parsed(parser.parse_bytes(raw, source=source))


def analyze_file(path: str | Path) -> OverallResult:
    """Parse an ``.eml`` / raw message file and return the overall verdict."""
    path = Path(path)
    return analyze_parsed(parser.parse_file(path))
