
from .models import (
    EmailAddress,
    Finding,
    ModuleResult,
    OverallResult,
    ParsedEmail,
)
from .pipeline import analyze_bytes, analyze_file, analyze_parsed

__version__ = "1.0.0"

__all__ = [
    "analyze_file",
    "analyze_bytes",
    "analyze_parsed",
    "ParsedEmail",
    "EmailAddress",
    "Finding",
    "ModuleResult",
    "OverallResult",
]
