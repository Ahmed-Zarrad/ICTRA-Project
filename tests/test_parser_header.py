

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phish_analyzer import header_analysis, parser  # noqa: E402

DATASET = Path(__file__).resolve().parent.parent / "phishing_pot-main" / "email"


# Synthetic fixtures

LEGIT_AUTHENTICATED = b"""\
Return-Path: <bounces@github.com>
Authentication-Results: spf=pass (sender IP is 192.30.252.1)
 smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass
 action=none header.from=github.com;compauth=pass reason=000
From: GitHub <noreply@github.com>
To: dev@example.com
Subject: [GitHub] Your weekly digest
Message-ID: <abc123@github.com>
Date: Tue, 10 Jun 2025 09:00:00 +0000
Content-Type: text/plain; charset=UTF-8

Here is your weekly activity digest.
"""

# An old Enron-style message: no SPF/DKIM/DMARC at all, internal Message-ID host.
ENRON_STYLE = b"""\
Message-ID: <1234567.1075840000000.JavaMail.evans@thyme>
Date: Mon, 14 May 2001 16:39:00 -0700 (PDT)
From: phillip.allen@enron.com
To: tim.belden@enron.com
Subject: Re: West Power Position
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii

Tim, the numbers look fine. Let's discuss tomorrow.
"""


def check(name: str, condition: bool, extra: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f"  -- {extra}" if extra else ""))
    return condition


def run() -> int:
    failures = 0

    print("legitimate authenticated mail should score very low:")
    r = header_analysis.analyze(parser.parse_bytes(LEGIT_AUTHENTICATED, "legit"))
    failures += not check("score < 10", r.score < 10, f"score={r.score}")
    failures += not check(
        "no high/medium findings",
        all(f.severity in ("info", "low") for f in r.findings),
        f"findings={[f.code for f in r.findings]}",
    )

    print("Enron-style mail (no auth headers) must not be penalised:")
    r = header_analysis.analyze(parser.parse_bytes(ENRON_STYLE, "enron"))
    failures += not check("score < 10", r.score < 10, f"score={r.score}")
    failures += not check(
        "absence of auth headers adds 0 points",
        any(f.code == "AUTH_ABSENT" and f.points == 0 for f in r.findings),
    )

    print("known phishing samples should score high:")
    expectations = {
        "sample-1.eml": ("FROM_DISPLAY_BRAND_SPOOF", 50),    # Bradesco impersonation
        "sample-50.eml": ("REPLYTO_FREEMAIL", 50),           # fake Facebook, reply->gmail
        "sample-2000.eml": ("FROM_DISPLAY_BRAND_SPOOF", 50),  # Temu, comma-trick + mismatch
    }
    for fname, (expected_code, min_score) in expectations.items():
        path = DATASET / fname
        if not path.exists():
            print(f"  [SKIP] {fname} (dataset not present)")
            continue
        r = header_analysis.analyze(parser.parse_file(path))
        codes = {f.code for f in r.findings}
        failures += not check(f"{fname}: score >= {min_score}", r.score >= min_score,
                              f"score={r.score}")
        failures += not check(f"{fname}: flags {expected_code}", expected_code in codes,
                              f"codes={sorted(codes)}")

    print()
    if failures:
        print(f"RESULT: {failures} check(s) FAILED")
    else:
        print("RESULT: all checks passed")
    return failures


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
