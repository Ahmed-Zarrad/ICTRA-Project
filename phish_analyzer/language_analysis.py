

from __future__ import annotations

import re

from .models import Finding, ModuleResult, ParsedEmail, severity_for_points

MODULE_NAME = "language"


_LURE_CATEGORIES: list[tuple[str, str, int, int, list[tuple[str, str]]]] = [
    (
        "LANG_URGENCY", "Manufactured urgency / time pressure", 6, 18,
        [
            ("urgent", r"\burgent(?:ly)?\b"),
            ("immediately", r"\bimmediately\b"),
            ("act now", r"\bact now\b"),
            ("action required", r"\baction (?:is )?required\b"),
            ("expires/expiring", r"\bexpir(?:e|es|ing|ation)\b"),
            ("within 24/48 hours", r"\bwithin \d+\s*(?:hours|hrs|days)\b"),
            ("last/final notice", r"\b(?:last|final) (?:notice|warning|reminder)\b"),
            ("time sensitive", r"\btime[- ]sensitive\b"),
            ("do not delay", r"\bdo not (?:delay|ignore)\b"),
            ("as soon as possible", r"\bas soon as possible\b"),
        ],
    ),
    (
        "LANG_THREAT", "Account threat / consequence", 7, 20,
        [
            ("suspended", r"\bsuspend(?:ed|ing|sion)?\b"),
            ("deactivated", r"\bdeactivat(?:e|ed|ion)\b"),
            ("account locked/closed/disabled",
             r"\baccount (?:has been |will be |is )?(?:lock|clos|disabl|terminat|"
             r"suspend|limit|restrict)"),
            ("unauthorized access",
             r"\bunauthori[sz]ed (?:access|login|attempt|activity|transaction)\b"),
            ("unusual activity",
             r"\bunusual (?:activity|sign[- ]?in|login|attempt)\b"),
            ("we detected/noticed",
             r"\bwe (?:have )?(?:detected|noticed|found)\b.{0,40}\b"
             r"(?:activity|login|sign[- ]?in|access)\b"),
            ("security alert", r"\bsecurity (?:alert|notice|warning)\b"),
            ("permanently deleted/closed",
             r"\bpermanently (?:delet|clos|disabl|suspend)"),
        ],
    ),
    (
        "LANG_CREDENTIAL", "Credential-harvesting lure", 8, 22,
        [
            ("verify your account/identity",
             r"\bverify your (?:account|identity|information|email|details|payment)\b"),
            ("confirm your account/identity",
             r"\bconfirm your (?:account|identity|password|information|details)\b"),
            ("update your account/password",
             r"\bupdate your (?:account|password|payment|billing|information|details)\b"),
            ("validate your", r"\bvalidate your (?:account|identity|information)\b"),
            ("reactivate your account", r"\bre[- ]?activate your (?:account|access)\b"),
            ("log in to confirm/secure",
             r"\b(?:log ?in|sign ?in) to (?:confirm|verify|secure|continue|restore|update)\b"),
            ("click to verify/update",
             r"\bclick (?:here|the link|below|this link)\b.{0,40}\b"
             r"(?:verify|confirm|update|secure|account|password|login)\b"),
        ],
    ),
    (
        "LANG_SENSITIVE", "Request for sensitive information", 10, 20,
        [
            ("social security / SSN", r"\b(?:social security|ssn)\b"),
            ("card number / CVV", r"\b(?:credit card number|card number|cvv|cvc)\b"),
            ("PIN", r"\bpin (?:number|code)\b"),
            ("one-time password/OTP", r"\b(?:one[- ]time (?:password|code|pin)|otp)\b"),
            ("banking details",
             r"\bbank(?:ing)? (?:details|information|credentials|account number)\b"),
            ("mother's maiden name", r"\bmother'?s maiden name\b"),
        ],
    ),
    (
        "LANG_REWARD", "Reward / financial bait", 6, 16,
        [
            ("you have won", r"\byou(?:'ve| have)? won\b"),
            ("claim your prize/reward",
             r"\bclaim your (?:prize|reward|refund|money|gift|winnings)\b"),
            ("gift card", r"\bgift card\b"),
            ("lottery / winner", r"\b(?:lottery|you are a winner|lucky winner)\b"),
            ("inheritance / beneficiary", r"\b(?:inheritance|beneficiary)\b"),
            ("wire transfer / millions",
             r"\b(?:wire transfer|\d+\s*million (?:dollars|usd|euros))\b"),
            ("tax/refund pending",
             r"\b(?:tax )?refund\b.{0,30}\b(?:pending|approved|owed|waiting)\b"),
            ("crypto bait", r"\b(?:bitcoin|cryptocurrency)\b.{0,30}\b(?:gift|free|double|claim)\b"),
        ],
    ),
    (
        "LANG_GREETING", "Impersonal mass-mail greeting", 8, 8,
        [
            ("dear customer/user",
             r"\bdear (?:customer|user|client|member|account holder|"
             r"valued (?:customer|member)|sir/madam|email user)\b"),
        ],
    ),
   
    (
        "LANG_FOREIGN_LURE", "Coercive wording (non-English)", 6, 18,
        [
            # Portuguese
            ("conta suspensa/bloqueada", r"conta (?:suspensa|bloqueada|foi|sera)"),
            ("verificar/atualizar conta", r"(?:verificar|confirmar|atualiz\w*|regulariz\w*) (?:sua |seus |a sua )?(?:conta|dados|cadastro)"),
            ("clique aqui", r"clique (?:aqui|no link|no bot)"),
            ("restituicao/IRPF/receita", r"(?:restitui\w+|irpf|receita federal|imposto de renda)"),
            ("saldo liberado/reembolso", r"(?:saldo liberado|liberado|reembolso|pend\w*ncia)"),
            ("voce ganhou/premio", r"(?:voc[eê] ganhou|pr[eê]mio|sorteado)"),
            ("urgente (pt/es)", r"\burgente\b"),
            # Spanish
            ("su cuenta", r"su cuenta (?:ha sido|sera|fue|est)"),
            ("verifique/haga clic", r"(?:verifique su cuenta|haga clic|inicie sesi)"),
            ("contrasena", r"contrase[nñ]a"),
            # German
            ("ihr konto", r"ihr konto (?:wurde|ist|wird)"),
            ("bestatigen/verifizieren", r"(?:best[aä]tigen|verifizieren|aktualisieren)"),
            ("klicken sie", r"klicken sie"),
            ("dringend/gesperrt", r"(?:dringend|gesperrt|passwort)"),
        ],
    ),
]


_SYNERGY_CODES = {"LANG_URGENCY", "LANG_THREAT", "LANG_CREDENTIAL",
                  "LANG_SENSITIVE", "LANG_REWARD", "LANG_FOREIGN_LURE"}
POINTS_SYNERGY_2 = 4
POINTS_SYNERGY_3PLUS = 10


POINTS_SHOUTING_SUBJECT = 6
POINTS_EXCESS_PUNCT = 6

_COMPILED: list[tuple[str, str, int, int, list[tuple[str, re.Pattern]]]] = [
    (code, title, per_hit, cap, [(label, re.compile(rx, re.IGNORECASE))
                                 for label, rx in phrases])
    for code, title, per_hit, cap, phrases in _LURE_CATEGORIES
]



# The analyzer

def analyze(email: ParsedEmail) -> ModuleResult:
    """Run all language checks and return a :class:`ModuleResult` (score 0-100)."""
    result = ModuleResult(name=MODULE_NAME)

    subject = email.subject or ""
    # Collapse whitespace so phrases split across wrapped lines still match.
    corpus = re.sub(r"\s+", " ", f"{subject}\n{email.body_text or ''}").strip()
    result.facts["chars_analyzed"] = len(corpus)

    fired_synergy: list[str] = []
    for code, title, per_hit, cap, phrases in _COMPILED:
        matched = [label for label, rx in phrases if rx.search(corpus)]
        if not matched:
            continue
        points = min(cap, per_hit * len(matched))
        _emit(result, code, title,
              f"Wording matches {title.lower()}: {', '.join(matched)}.",
              points)
        if code in _SYNERGY_CODES:
            fired_synergy.append(code)

    _check_synergy(result, fired_synergy)
    _check_style(result, subject)

    return result.finalize()


def _emit(result: ModuleResult, code: str, title: str, detail: str, points: int,
          severity: str | None = None) -> None:
    sev = severity or severity_for_points(points)
    result.add(Finding(code=code, title=title, detail=detail, severity=sev, points=points))
    result.score += points


def _check_synergy(result: ModuleResult, fired: list[str]) -> None:
    n = len(fired)
    if n >= 3:
        points = POINTS_SYNERGY_3PLUS
    elif n == 2:
        points = POINTS_SYNERGY_2
    else:
        return
    _emit(result, "LANG_MULTI_CATEGORY", "Multiple manipulation tactics combined",
          f"The message stacks {n} distinct coercion tactics "
          f"({', '.join(c.replace('LANG_', '').lower() for c in fired)}) -- a "
          "pattern characteristic of phishing rather than ordinary mail.",
          points)


def _check_style(result: ModuleResult, subject: str) -> None:
    words = re.findall(r"[A-Za-z]{4,}", subject)
    shouting = [w for w in words if w.isupper()]
    if len(shouting) >= 2 or (words and len(shouting) / len(words) >= 0.6 and len(words) >= 2):
        _emit(result, "LANG_SHOUTING", "Subject line shouts in all caps",
              f'Subject relies on all-caps words for pressure: "{subject[:80]}".',
              points=POINTS_SHOUTING_SUBJECT)

    if re.search(r"[!?]{3,}", subject) or subject.count("!") >= 3:
        _emit(result, "LANG_EXCESS_PUNCT", "Excessive punctuation",
              f'Subject uses excessive punctuation for emphasis: "{subject[:80]}".',
              points=POINTS_EXCESS_PUNCT)
