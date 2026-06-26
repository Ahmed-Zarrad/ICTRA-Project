

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from . import report
from .models import OverallResult
from .pipeline import analyze_file

# ANSI colours per band (skipped automatically when stdout is not a TTY).
_BAND_ANSI = {
    "low": "\033[32m", "medium": "\033[33m",
    "high": "\033[35m", "critical": "\033[31m",
}
_RESET = "\033[0m"


def _color(text: str, band: str, enable: bool) -> str:
    return f"{_BAND_ANSI.get(band, '')}{text}{_RESET}" if enable else text


def print_summary(result: OverallResult, use_color: bool) -> None:
    email = result.email
    band = result.band.upper()
    print("=" * 72)
    print(f"file    : {email.source}")
    print(f"from    : {email.from_addr or '(none)'}")
    print(f"subject : {(email.subject or '(none)')[:66]}")
    print(
        "verdict : "
        + _color(f"{band}  ({result.score}/100)", result.band, use_color)
    )
    parts = "   ".join(f"{m.name}={m.score}" for m in result.modules)
    print(f"modules : {parts}")
    scored = [f for f in result.findings if f.points > 0]
    if scored:
        print("findings:")
        for f in scored:
            print(f"  [{f.severity:^6}] +{f.points:<3} {f.title}")
            print(f"           {f.detail}")
    else:
        print("findings: (none -- looks legitimate)")
    print()


def _force_utf8_stdio() -> None:
    
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str]) -> int:
    _force_utf8_stdio()
    ap = argparse.ArgumentParser(
        prog="phish_analyzer",
        description="Rule-based phishing email risk analyzer.",
    )
    ap.add_argument("emails", nargs="+", help="email file(s) to analyse (.eml or raw)")
    ap.add_argument("--html", metavar="PATH",
                    help="write an HTML report (for a single input file)")
    ap.add_argument("--html-dir", metavar="DIR",
                    help="write one HTML report per input into DIR")
    ap.add_argument("--open", action="store_true",
                    help="open the generated HTML report in a browser")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args(argv)

    use_color = sys.stdout.isatty() and not args.no_color
    exit_code = 0

    for raw_path in args.emails:
        path = Path(raw_path)
        if not path.exists():
            print(f"!! not found: {path}", file=sys.stderr)
            exit_code = 2
            continue
        result = analyze_file(path)
        print_summary(result, use_color)

        out_path: Path | None = None
        if args.html_dir:
            out_path = report.write_html(result, Path(args.html_dir) / f"{path.stem}.html")
        elif args.html:
            out_path = report.write_html(result, args.html)
        if out_path:
            print(f"  -> HTML report: {out_path}")
            if args.open:
                webbrowser.open(out_path.resolve().as_uri())

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
