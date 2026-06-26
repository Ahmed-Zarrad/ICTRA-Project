

from __future__ import annotations

import random
import sys
from pathlib import Path

# Make the package importable when run as a plain script from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phish_analyzer import header_analysis, parser  # noqa: E402

DATASET = Path(__file__).resolve().parent.parent / "phishing_pot-main" / "email"


def show(path: Path) -> None:
    email = parser.parse_file(path)
    result = header_analysis.analyze(email)

    print("=" * 78)
    print(f"file       : {path.name}")
    print(f"subject    : {email.subject[:72]}")
    print(f"from       : {email.from_addr}")
    print(f"reply-to   : {email.reply_to or '(none)'}")
    print(f"return-path: {email.return_path or '(none)'}")
    print(f"auth       : {result.facts.get('auth')}")
    print(f"links found: {len(email.links)}")
    print(f"\nHEADER RISK SCORE: {result.score}/100")
    if result.findings:
        print("findings:")
        for f in result.findings:
            print(f"  [{f.severity:^6}] +{f.points:<3} {f.title}")
            print(f"           {f.detail}")
    else:
        print("findings: (none)")
    print()


def main(argv: list[str]) -> None:
    if argv and argv[0] == "--random":
        n = int(argv[1]) if len(argv) > 1 else 5
        paths = random.sample(sorted(DATASET.glob("*.eml")), n)
    elif argv:
        paths = [Path(a) for a in argv]
    else:
        # Hand-picked: each exhibits a different classic signal.
        names = ["sample-1.eml", "sample-50.eml", "sample-500.eml", "sample-2000.eml"]
        paths = [DATASET / n for n in names]

    for p in paths:
        if p.exists():
            show(p)
        else:
            print(f"!! not found: {p}")


if __name__ == "__main__":
    main(sys.argv[1:])
