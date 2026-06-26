
from __future__ import annotations

import re

from .domains import FREEMAIL_DOMAINS, is_freemail, registered_domain
from .models import Finding, ModuleResult, ParsedEmail, severity_for_points

MODULE_NAME = "header"


SPF_POINTS = {
    "pass": 0, "neutral": 8, "none": 10, "softfail": 18, "fail": 28,
    "temperror": 4, "permerror": 6,
}
DKIM_POINTS = {
    "pass": 0, "none": 14, "fail": 26, "neutral": 6, "temperror": 3, "permerror": 5,
}
DMARC_POINTS = {
    "pass": 0, "bestguesspass": 4, "none": 16, "fail": 30, "temperror": 4, "permerror": 6,
}
COMPAUTH_POINTS = {"pass": 0, "softpass": 10, "none": 8, "fail": 26}

POINTS_FROM_EMPTY = 26          
POINTS_DISPLAY_BRAND_SPOOF = 24  
POINTS_DISPLAY_EMBEDS_ADDR = 14 
POINTS_FREEMAIL_ORG = 26         
POINTS_RETURNPATH_MISMATCH = 8   
POINTS_REPLYTO_MISMATCH = 8      
POINTS_REPLYTO_FREEMAIL = 22     
POINTS_DKIM_UNALIGNED = 14       

POINTS_MSGID_MISMATCH = 0       


IMPERSONATED_BRANDS: frozenset[str] = frozenset(
    {
        "paypal", "microsoft", "office365", "outlook", "apple", "icloud", "amazon",
        "google", "facebook", "instagram", "whatsapp", "linkedin", "netflix",
        "dhl", "fedex", "ups", "usps", "dpd", "correos",
        "chase", "wellsfargo", "citibank", "hsbc", "barclays", "santander",
        "bradesco", "itau", "nubank", "bankofamerica", "amex",
        "irs", "hmrc", "docusign", "dropbox", "coinbase", "binance", "metamask",
        "netflix", "spotify", "temu", "shein", "walmart", "target",
        
        "ripple", "kraken", "blockchain", "trustwallet", "ledger", "exodus",
        "wise", "revolut", "monzo", "venmo", "zelle", "cashapp", "stripe",
        "att", "verizon", "comcast", "xfinity", "norton", "mcafee", "geeksquad",
        "steam", "discord", "roblox", "ebay", "adobe", "aliexpress", "mercadolibre",
    }
)


ORG_DISPLAY_KEYWORDS: frozenset[str] = frozenset(
    {
        "bank", "banco", "account", "conta", "support", "suporte", "soporte",
        "service", "services", "servico", "servicio", "security", "seguranca",
        "seguridad", "alert", "alerta", "notification", "notificacao",
        "notificacion", "billing", "invoice", "fatura", "factura", "refund",
        "reembolso", "irs", "receita", "hacienda", "official", "oficial", "team",
        "equipe", "helpdesk", "customer", "cliente", "verification",
        "verificacao", "verificacion", "atendimento", "noreply", "premio",
        "prize", "reward", "update", "atualizacao", "gov", "department",
    }
)


_AUTH_KEYS = ("spf", "dkim", "dmarc", "compauth")



def parse_auth_results(auth_values: list[str], received_spf: str = "") -> dict:
    """Extract structured verdicts from Authentication-Results header text.

    Returns a dict that may contain: spf, dkim, dmarc, compauth (verdict words)
    plus spf_domain (smtp.mailfrom), dkim_domain (header.d), header_from
    (header.from). Missing keys simply are not present.
    """
    text = " ".join(auth_values)
    out: dict[str, str] = {}

    for key in _AUTH_KEYS:
        m = re.search(rf"\b{key}\s*=\s*([a-zA-Z]+)", text)
        if m:
            out[key] = m.group(1).lower()

    for key, pattern in (
        ("dkim_domain", r"header\.d\s*=\s*([^\s;]+)"),
        ("spf_domain", r"smtp\.mailfrom\s*=\s*([^\s;]+)"),
        ("header_from", r"header\.from\s*=\s*([^\s;]+)"),
    ):
        m = re.search(pattern, text)
        if m:
            out[key] = m.group(1).strip().lower()

    # Received-SPF is a useful corroborating fallback when SPF wasn't in A-R.
    if "spf" not in out and received_spf:
        m = re.search(r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b",
                      received_spf, re.IGNORECASE)
        if m:
            out["spf"] = m.group(1).lower()

    return out


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


_LIST_HEADERS = ("list-id", "list-unsubscribe", "list-post", "list-help",
                 "mailing-list")


def _is_bulk_or_list(email: ParsedEmail) -> bool:
    """True for mailing-list / bulk mail, which legitimately rewrites the
    envelope sender and Reply-To (so those mismatches are not suspicious)."""
    headers = email.headers
    if any(key in headers for key in _LIST_HEADERS):
        return True
    precedence = " ".join(headers.get("precedence", [])).lower()
    return "list" in precedence or "bulk" in precedence



# The analyzer

def analyze(email: ParsedEmail) -> ModuleResult:
    """Run all header checks and return a :class:`ModuleResult` (score 0-100)."""
    result = ModuleResult(name=MODULE_NAME)

    from_addr = email.from_addr
    from_domain = from_addr.domain if from_addr else ""
    from_rd = registered_domain(from_domain)

    auth = parse_auth_results(email.auth_results, email.received_spf)
    result.facts["auth"] = auth
    result.facts["from"] = str(from_addr) if from_addr else "(none)"
    result.facts["from_domain"] = from_domain

    _check_authentication(result, auth, bool(email.auth_results or email.received_spf))
    _check_sender_identity(result, email, from_addr, from_domain, from_rd)
    _check_alignment(result, email, auth, from_domain, from_rd)

    return result.finalize()


def _emit(result: ModuleResult, code: str, title: str, detail: str, points: int,
          severity: str | None = None) -> None:
    sev = severity or severity_for_points(points)
    result.add(Finding(code=code, title=title, detail=detail, severity=sev, points=points))
    result.score += points


#1. authentication
def _check_authentication(result: ModuleResult, auth: dict, has_auth_headers: bool) -> None:
    if not has_auth_headers:
        
        _emit(result, "AUTH_ABSENT", "No authentication results",
              "Message carries no SPF/DKIM/DMARC results; sender authenticity "
              "could not be verified from headers.", points=0, severity="info")
        return

    verdict_specs = (
        ("spf", "SPF", SPF_POINTS),
        ("dkim", "DKIM", DKIM_POINTS),
        ("dmarc", "DMARC", DMARC_POINTS),
        ("compauth", "Composite auth", COMPAUTH_POINTS),
    )
    all_pass = True
    for key, label, table in verdict_specs:
        verdict = auth.get(key)
        if verdict is None:
            continue
        points = table.get(verdict, 6) 
        if verdict != "pass":
            all_pass = False
        if points > 0:
            _emit(result, f"{key.upper()}_{verdict.upper()}",
                  f"{label} = {verdict}",
                  f"{label} authentication returned '{verdict}'.", points)

    if all_pass and any(k in auth for k in _AUTH_KEYS):
        _emit(result, "AUTH_PASS", "Sender authentication passed",
              "SPF/DKIM/DMARC results present and all passing.",
              points=0, severity="info")


# 2. sender sanity 
def _check_sender_identity(result: ModuleResult, email: ParsedEmail,
                           from_addr, from_domain: str, from_rd: str) -> None:
    display = from_addr.display if from_addr else ""

    if from_addr is None or from_addr.is_empty:
        _emit(result, "FROM_EMPTY", "From address is empty/malformed",
              "The From header has no real address"
              + (f' (display name: "{display}")' if display else "")
              + " -- a common spoofing trick.",
              points=POINTS_FROM_EMPTY)
        

    if not display:
        return

    # Display name embeds an address or URL (e.g. "support@paypal.com" as name).
    if "@" in display or re.search(r"https?://", display, re.IGNORECASE):
        _emit(result, "FROM_DISPLAY_EMBEDS_ADDR", "Display name embeds an address/URL",
              f'From display name contains an embedded address or link: "{display}".',
              points=POINTS_DISPLAY_EMBEDS_ADDR)

    # Brand name in display that the real domain does not back up.
    display_tokens = _tokens(display)
    domain_flat = from_rd.replace(".", "")
    from_is_freemail = bool(from_domain) and is_freemail(from_domain)

    spoofed_brand = next(
        (b for b in IMPERSONATED_BRANDS if b in display_tokens and b not in domain_flat),
        None,
    )
    if spoofed_brand:
        where = f'the sending domain is "{from_domain}"' if from_domain \
            else "the message has no verifiable sender domain"
        extra = " and is sent from free webmail" if from_is_freemail else ""
        _emit(result, "FROM_DISPLAY_BRAND_SPOOF", "Display name impersonates a brand",
              f'Display name claims "{display}" but {where}{extra} '
              f'(no "{spoofed_brand}" relationship).',
              points=POINTS_DISPLAY_BRAND_SPOOF)
        return

    # No listed brand, but an organisation/notification display name arriving
    # from a free webmail account is itself a classic impersonation pattern.
    if from_is_freemail and _looks_organisational(display, display_tokens):
        _emit(result, "FROM_FREEMAIL_ORG", "Organisation name sent from free webmail",
              f'From shows an organisational/notification name ("{display}") but the '
              f'real address is free webmail ({from_domain}); legitimate '
              "organisations do not send from consumer webmail.",
              points=POINTS_FREEMAIL_ORG)


def _looks_organisational(display: str, display_tokens: set[str]) -> bool:
    """Heuristic: a From display name that reads like a company/notification
    rather than a private individual (used only when the sender is freemail)."""
    if display_tokens & ORG_DISPLAY_KEYWORDS:
        return True
    if "[" in display or "]" in display:        # "[BB] - Seu saldo ..."
        return True
    if any(ch.isdigit() for ch in display) and len(display.split()) >= 2:
        return True
    return len(display.split()) >= 5            # long notification-style strings


#  3. identity alignment 
def _check_alignment(result: ModuleResult, email: ParsedEmail, auth: dict,
                     from_domain: str, from_rd: str) -> None:
    is_list = _is_bulk_or_list(email)

    # Reply-To diverted to free webmail is a tell even when From is empty/forged,
    # so evaluate it before the "needs a From to compare against" checks.
    rt = email.reply_to
    if rt and rt.domain:
        rt_rd = registered_domain(rt.domain)
        if from_rd and rt_rd != from_rd:
            if is_freemail(rt.domain) and not is_freemail(from_domain):
                _emit(result, "REPLYTO_FREEMAIL", "Reply-To diverted to free webmail",
                      f"Replies are directed to '{rt.addr}' (free webmail) while the "
                      f"sender claims to be '{from_domain}'.",
                      points=POINTS_REPLYTO_FREEMAIL)
            elif not is_list:
                _emit(result, "REPLYTO_MISMATCH", "Reply-To domain differs from From",
                      f"Reply-To domain '{rt.domain}' does not match From domain "
                      f"'{from_domain}'.",
                      points=POINTS_REPLYTO_MISMATCH)
        elif not from_rd and is_freemail(rt.domain):
            _emit(result, "REPLYTO_FREEMAIL", "Reply-To diverted to free webmail",
                  f"Replies are directed to '{rt.addr}' (free webmail) but the "
                  f"sender provides no verifiable address.",
                  points=POINTS_REPLYTO_FREEMAIL)

    if not from_rd:
        return

    # Return-Path (envelope sender) vs From only when not list/bulk mail.
    rp = email.return_path
    if rp and rp.domain and not is_list:
        rp_rd = registered_domain(rp.domain)
        if rp_rd and rp_rd != from_rd:
            _emit(result, "RETURNPATH_MISMATCH", "Return-Path domain differs from From",
                  f"Envelope sender (Return-Path) is '{rp.domain}' but the visible "
                  f"From domain is '{from_domain}'.",
                  points=POINTS_RETURNPATH_MISMATCH)

    # DKIM signed but not aligned with the visible sender (DMARC-style alignment).
    if auth.get("dkim") == "pass":
        dkim_domain = auth.get("dkim_domain", "")
        if dkim_domain and dkim_domain != "none":
            dkim_rd = registered_domain(dkim_domain)
            if dkim_rd and dkim_rd != from_rd:
                _emit(result, "DKIM_UNALIGNED", "DKIM signature not aligned with From",
                      f"DKIM passed for '{dkim_domain}' but the From domain is "
                      f"'{from_domain}' -- the signature does not vouch for the sender.",
                      points=POINTS_DKIM_UNALIGNED)

    # Message-ID generated by a different domain than the sender.
    mid_rd = registered_domain(email.message_id_domain)
    if mid_rd and from_rd and mid_rd != from_rd:
        _emit(result, "MSGID_MISMATCH", "Message-ID domain differs from From",
              f"Message-ID was generated by '{email.message_id_domain}', not the "
              f"sender domain '{from_domain}'.",
              points=POINTS_MSGID_MISMATCH)
