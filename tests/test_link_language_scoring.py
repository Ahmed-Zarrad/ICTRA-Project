"""Regression tests for the link, language, scoring and pipeline modules.

Runs with plain Python (no pytest needed):

    python tests/test_link_language_scoring.py

As with the header tests, the legitimate cases matter most: they prove the new
modules do not over-flag ordinary mail. Several cases are explicit regression
guards for false positives found during evaluation (short-brand look-alikes,
mailing-list envelope rewrites).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phish_analyzer import language_analysis, link_analysis, parser, scoring  # noqa: E402
from phish_analyzer.models import ModuleResult  # noqa: E402
from phish_analyzer.pipeline import analyze_bytes  # noqa: E402


def check(name: str, condition: bool, extra: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f"  -- {extra}" if extra else ""))
    return condition


def _email_with_links(links_html: str) -> object:
    raw = (
        b"From: Service <info@example-shop.com>\r\n"
        b"To: user@example.com\r\nSubject: Notice\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n\r\n"
        + f"<html><body>{links_html}</body></html>".encode()
    )
    return parser.parse_bytes(raw, "synthetic")


def _codes(result: ModuleResult) -> set[str]:
    return {f.code for f in result.findings}


# --------------------------------------------------------------------------- #
def test_links(failures: list[int]) -> None:
    print("link analysis -- malicious URLs should be flagged:")
    cases = [
        ('<a href="http://paypa1.com/login">verify</a>', "URL_LOOKALIKE"),
        ('<a href="http://192.0.2.10/verify">verify</a>', "URL_IP_HOST"),
        ('<a href="http://paypal.com@evil.ru/">verify</a>', "URL_AT_TRICK"),
        ('<a href="http://paypal-security.com/">verify</a>', "URL_BRAND_MISMATCH"),
        ('<a href="http://evil.ru/x">www.paypal.com</a>', "ANCHOR_HREF_MISMATCH"),
    ]
    for html, expected in cases:
        r = link_analysis.analyze(_email_with_links(html))
        failures.append(not check(f"flags {expected}", expected in _codes(r),
                                  f"codes={sorted(_codes(r))} score={r.score}"))

    print("link analysis -- legitimate URLs must NOT be flagged:")
    legit = [
        '<a href="http://www.redhat.com/support">docs</a>',
        '<a href="http://www.msnbc.com/news">news</a>',   # regression: msnbc != hsbc
        '<a href="http://online.wsj.com/article">read</a>',  # regression: wsj != wise
        '<a href="https://lists.sourceforge.net/list">unsubscribe</a>',
    ]
    for html in legit:
        r = link_analysis.analyze(_email_with_links(html))
        failures.append(not check(f"clean: {html[:48]}...", r.score == 0,
                                  f"score={r.score} codes={sorted(_codes(r))}"))


def test_language(failures: list[int]) -> None:
    print("language analysis -- coercive wording should score high:")
    phish = (
        "URGENT: Your account has been suspended due to unusual activity. "
        "Verify your account immediately or it will be permanently closed. "
        "Click here to confirm your identity."
    )
    raw = b"From: x@y.com\r\nSubject: URGENT account alert!!!\r\n\r\n" + phish.encode()
    r = language_analysis.analyze(parser.parse_bytes(raw))
    failures.append(not check("score >= 30", r.score >= 30, f"score={r.score}"))
    failures.append(not check("fires synergy (multi-category)",
                             "LANG_MULTI_CATEGORY" in _codes(r),
                             f"codes={sorted(_codes(r))}"))

    print("language analysis -- non-English lure (Portuguese) should score:")
    pt = ("Sua conta foi bloqueada. Confirme seus dados e clique aqui para "
          "regularizar sua restituicao do IRPF. Urgente.")
    r = language_analysis.analyze(parser.parse_bytes(b"Subject: Aviso\r\n\r\n" + pt.encode()))
    failures.append(not check("foreign lure flagged", r.score >= 12, f"score={r.score}"))

    print("language analysis -- ordinary technical mail must stay low:")
    legit = ("Re: patch v2 for the scheduler. I updated the config and rebuilt; "
             "the password hashing test now passes. Please review when you can.")
    r = language_analysis.analyze(parser.parse_bytes(b"Subject: Re: patch v2\r\n\r\n" + legit.encode()))
    failures.append(not check("legit tech mail score low (<8)", r.score < 8,
                             f"score={r.score} codes={sorted(_codes(r))}"))


def test_scoring(failures: list[int]) -> None:
    print("scoring -- band thresholds:")
    failures.append(not check("0 -> low", scoring.band_for_score(0) == "low"))
    failures.append(not check("30 -> medium", scoring.band_for_score(30) == "medium"))
    failures.append(not check("60 -> high", scoring.band_for_score(60) == "high"))
    failures.append(not check("90 -> critical", scoring.band_for_score(90) == "critical"))

    print("scoring -- a single decisive module still raises the overall band:")
    modules = [ModuleResult("header", score=84), ModuleResult("link", score=0),
               ModuleResult("language", score=0)]
    overall = scoring.combine(None, modules)
    failures.append(not check("one strong module -> high+", overall.band in ("high", "critical"),
                             f"score={overall.score} band={overall.band}"))

    print("scoring -- all-low modules stay low:")
    modules = [ModuleResult("header", score=0), ModuleResult("link", score=0),
               ModuleResult("language", score=4)]
    overall = scoring.combine(None, modules)
    failures.append(not check("all low -> low", overall.band == "low",
                             f"score={overall.score}"))


def test_pipeline(failures: list[int]) -> None:
    print("pipeline -- end-to-end fairness checks:")
    legit = (
        b"Return-Path: <author@lists.example.org>\r\n"
        b"List-Id: dev discussion <dev.lists.example.org>\r\n"
        b"From: Jane Dev <jane@example.org>\r\nReply-To: dev@lists.example.org\r\n"
        b"To: dev@lists.example.org\r\nSubject: Re: build flags\r\n\r\n"
        b"Looks good to me, merging after CI passes."
    )
    r = analyze_bytes(legit, "legit-list")
    failures.append(not check("legit mailing-list mail -> low", r.band == "low",
                             f"score={r.score} band={r.band}"))

    phish = (
        b"From: \"PayPal Support\" <secure@paypa1-account.com>\r\n"
        b"Reply-To: paypal-help@gmail.com\r\nTo: user@example.com\r\n"
        b"Subject: Your account has been suspended\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body>Verify your account immediately. "
        b'<a href="http://192.0.2.10/login">www.paypal.com</a></body></html>'
    )
    r = analyze_bytes(phish, "phish")
    failures.append(not check("multi-signal phishing -> high/critical",
                             r.band in ("high", "critical"),
                             f"score={r.score} band={r.band} "
                             f"modules={[(m.name, m.score) for m in r.modules]}"))


def run() -> int:
    failures: list[int] = []
    test_links(failures)
    test_language(failures)
    test_scoring(failures)
    test_pipeline(failures)
    total = sum(failures)
    print()
    print(f"RESULT: {total} check(s) FAILED" if total else "RESULT: all checks passed")
    return total


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
