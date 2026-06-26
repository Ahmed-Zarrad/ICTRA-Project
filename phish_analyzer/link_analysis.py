

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .domains import (
    hostname_of,
    is_ip_host,
    levenshtein,
    registered_domain,
)
from .models import Finding, ModuleResult, ParsedEmail, severity_for_points

MODULE_NAME = "link"


# Tunable weights  (points added to the 0-100 link risk score)

POINTS_IP_HOST = 30          
POINTS_AT_TRICK = 30         
POINTS_LOOKALIKE = 32        
POINTS_BRAND_MISMATCH = 28   
POINTS_ANCHOR_MISMATCH = 30  
POINTS_PUNYCODE = 16         
POINTS_SHORTENER = 8         
POINTS_SUSPICIOUS_TLD = 8    
POINTS_MANY_SUBDOMAINS = 6   


LOOKALIKE_MIN, LOOKALIKE_MAX = 1, 2
LOOKALIKE_MIN_BRAND_LEN = 5   
LOOKALIKE_DIST2_MIN_LEN = 8  
SUBDOMAIN_DEPTH_FLAG = 3     

# Characters phishers swap to forge a look-alike that the eye reads as the brand.
_HOMOGLYPH_MAP = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
     "9": "g", "|": "l", "!": "i"}
)


POPULAR_TARGET_DOMAINS: frozenset[str] = frozenset(
    {
        "paypal.com", "microsoft.com", "office.com", "live.com", "outlook.com",
        "apple.com", "icloud.com", "amazon.com", "google.com", "gmail.com",
        "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com",
        "netflix.com", "spotify.com", "ebay.com", "adobe.com", "dropbox.com",
        "docusign.com", "coinbase.com", "binance.com", "metamask.io",
        "dhl.com", "fedex.com", "ups.com", "usps.com", "dpd.com",
        "chase.com", "wellsfargo.com", "citibank.com", "hsbc.com",
        "barclays.com", "santander.com", "bankofamerica.com", "americanexpress.com",
        "bradesco.com.br", "itau.com.br", "nubank.com.br",
        "walmart.com", "target.com", "temu.com", "shein.com",
        "irs.gov", "hmrc.gov.uk",
        "ripple.com", "kraken.com", "blockchain.com", "ledger.com",
        "wise.com", "revolut.com", "venmo.com", "stripe.com",
        "att.com", "verizon.com", "xfinity.com", "norton.com", "mcafee.com",
        "steampowered.com", "discord.com", "roblox.com", "aliexpress.com",
    }
)

# Brand labels (the registrable name without its suffix) for the
# "brand planted in someone else's domain" check, plus a few extra spellings.
BRAND_LABELS: frozenset[str] = frozenset(
    {registered_domain(d).split(".")[0] for d in POPULAR_TARGET_DOMAINS}
    | {"office365", "windows", "amex", "wellsfargo", "bankofamerica"}
)

URL_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "bl.ink",
        "lnkd.in", "trib.al", "t.ly", "soo.gd", "s.id", "v.gd",
    }
)

# TLDs disproportionately abused for phishing / cheap throwaway registration.
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "zip", "mov", "xyz", "top", "club", "online", "site", "click", "link",
        "work", "live", "fit", "rest", "country", "kim", "gq", "tk", "ml", "cf",
        "ga", "buzz", "monster", "cam", "icu", "support", "review",
    }
)



# URL helpers

_HOST_IN_TEXT_RE = re.compile(
    r"\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE
)


def _netloc_of(url: str) -> str:
    
    value = url.strip()
    if "//" not in value:
        value = "//" + value
    return urlsplit(value).netloc


# Brand names (label before the suffix) long enough to matter for look-alikes.
_BRAND_NAMES: tuple[tuple[str, str], ...] = tuple(
    (registered_domain(d).split(".")[0], d)
    for d in POPULAR_TARGET_DOMAINS
    if len(registered_domain(d).split(".")[0]) >= LOOKALIKE_MIN_BRAND_LEN
)


def _canonical(name: str) -> str:
    """``paypa1`` / ``arnazon`` """
    return name.translate(_HOMOGLYPH_MAP).replace("rn", "m").replace("vv", "w")


def _lookalike_match(rd: str) -> tuple[str, int]:
    
    name = rd.split(".")[0]
    if len(name) < LOOKALIKE_MIN_BRAND_LEN:
        return "", 99
    cname = _canonical(name)
    best, best_dist = "", 99
    for bname, bdomain in _BRAND_NAMES:
        if bname == name or abs(len(bname) - len(name)) > 1:
            continue  # the brand itself, or too different in length to be a typo
        # A homoglyph swap that resolves exactly onto the brand (amaz0n, paypa1).
        if _canonical(bname) == cname:
            return bdomain, 1
        allowed = LOOKALIKE_MAX if len(bname) >= LOOKALIKE_DIST2_MIN_LEN else 1
        dist = levenshtein(name, bname, max_distance=allowed)
        if LOOKALIKE_MIN <= dist <= allowed and dist < best_dist:
            best, best_dist = bdomain, dist
    return best, best_dist


def _domain_in_text(text: str) -> str:
    
    m = _HOST_IN_TEXT_RE.search(text or "")
    return registered_domain(m.group(1)) if m else ""



# The analyzer

def analyze(email: ParsedEmail) -> ModuleResult:
    """Run all link checks and return a :class:`ModuleResult` (score 0-100)."""
    result = ModuleResult(name=MODULE_NAME)

  
    hosts: dict[str, str] = {}       
    netloc_has_at: set[str] = set()
    for url in email.links:
        host = hostname_of(url)
        if host and host not in hosts:
            hosts[host] = url
        if "@" in _netloc_of(url):
            netloc_has_at.add(host or url)

    result.facts["link_count"] = len(email.links)
    result.facts["unique_hosts"] = sorted(hosts)

    if not email.links:
        result.add(Finding("NO_LINKS", "No links in message",
                           "The email contains no URLs to evaluate.",
                           severity="info", points=0))
        return result.finalize()

    _check_destinations(result, hosts, netloc_has_at)
    _check_brand_deception(result, hosts)
    _check_anchor_mismatch(result, email)
    _check_weak_signals(result, hosts)

    return result.finalize()


def _emit(result: ModuleResult, code: str, title: str, detail: str, points: int,
          severity: str | None = None) -> None:
    sev = severity or severity_for_points(points)
    result.add(Finding(code=code, title=title, detail=detail, severity=sev, points=points))
    result.score += points


def _sample(hosts: list[str], limit: int = 3) -> str:
    """A short, readable sample of offending hosts for a finding's detail."""
    shown = ", ".join(hosts[:limit])
    return shown + (f" (+{len(hosts) - limit} more)" if len(hosts) > limit else "")


#  1. deceptive destinations 
def _check_destinations(result: ModuleResult, hosts: dict[str, str],
                        netloc_has_at: set[str]) -> None:
    ip_hosts = [h for h in hosts if is_ip_host(h)]
    if ip_hosts:
        _emit(result, "URL_IP_HOST", "Link points to a raw IP address",
              f"Link(s) target a bare IP instead of a domain: {_sample(ip_hosts)}. "
              "Legitimate brands link to named domains.",
              points=POINTS_IP_HOST)

    if netloc_has_at:
        _emit(result, "URL_AT_TRICK", "Link uses the user@host credential trick",
              "A URL embeds '@' in its authority, so the real destination is what "
              "follows the '@', not the trusted-looking text before it.",
              points=POINTS_AT_TRICK)

    puny = [h for h in hosts if "xn--" in h]
    if puny:
        _emit(result, "URL_PUNYCODE", "Internationalised (punycode) host",
              f"Host(s) use IDN/punycode encoding: {_sample(puny)}. These can "
              "render as look-alikes of Latin brand names (homograph attack).",
              points=POINTS_PUNYCODE)


#  2. brand deception 
def _check_brand_deception(result: ModuleResult, hosts: dict[str, str]) -> None:
    lookalikes: list[str] = []
    brand_misuse: list[str] = []

    for host in hosts:
        if is_ip_host(host):
            continue
        rd = registered_domain(host)
        if not rd or rd in POPULAR_TARGET_DOMAINS:
            continue 

        target, dist = _lookalike_match(rd)
        if target:
            lookalikes.append(f"{host} ~ {target}")
            continue 

       
        rd_name = rd.split(".")[0]
        name_tokens = {t for t in re.split(r"[^a-z0-9]+", rd_name) if t}
        for brand in name_tokens & BRAND_LABELS:
            if brand != rd_name:
                brand_misuse.append(f"{host} (brand '{brand}' in registered domain '{rd}')")
                break

    if lookalikes:
        _emit(result, "URL_LOOKALIKE", "Look-alike (typosquatted) brand domain",
              "Link host is a near-miss of a known brand domain "
              f"(edit distance {LOOKALIKE_MIN}-{LOOKALIKE_MAX}): {_sample(lookalikes)}.",
              points=POINTS_LOOKALIKE)

    if brand_misuse:
        _emit(result, "URL_BRAND_MISMATCH", "Brand name used in an unrelated domain",
              "A trusted brand name appears in a domain registered to someone "
              f"else: {_sample(brand_misuse)}.",
              points=POINTS_BRAND_MISMATCH)


#  3. display deception 
def _check_anchor_mismatch(result: ModuleResult, email: ParsedEmail) -> None:
    
    mismatches: list[str] = []
    seen: set[tuple[str, str]] = set()
    for text, href in email.anchors:
        if not href.lower().startswith(("http://", "https://")):
            continue
        shown_rd = _domain_in_text(text)         
        if shown_rd not in POPULAR_TARGET_DOMAINS:
            continue                              
        href_rd = registered_domain(hostname_of(href))
        if href_rd and shown_rd != href_rd and (shown_rd, href_rd) not in seen:
            seen.add((shown_rd, href_rd))
            mismatches.append(f"reads '{shown_rd}' -> goes to '{href_rd}'")

    if mismatches:
        _emit(result, "ANCHOR_HREF_MISMATCH", "Link text impersonates a trusted brand",
              "Visible link text names a trusted brand domain but the link opens "
              f"a different domain: {_sample(mismatches)}.",
              points=POINTS_ANCHOR_MISMATCH)


#  4. weak signals 
def _check_weak_signals(result: ModuleResult, hosts: dict[str, str]) -> None:
    shorteners = [h for h in hosts if registered_domain(h) in URL_SHORTENERS]
    if shorteners:
        _emit(result, "URL_SHORTENER", "URL shortener hides the destination",
              f"Link(s) use a URL shortener: {_sample(shorteners)}. The true "
              "target cannot be inspected before clicking.",
              points=POINTS_SHORTENER)

    bad_tld = [h for h in hosts
               if not is_ip_host(h) and h.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS]
    if bad_tld:
        _emit(result, "URL_SUSPICIOUS_TLD", "Abuse-prone top-level domain",
              f"Link host(s) use a TLD frequently abused for phishing: {_sample(bad_tld)}.",
              points=POINTS_SUSPICIOUS_TLD)

    deep = []
    for host in hosts:
        if is_ip_host(host):
            continue
        rd = registered_domain(host)
        extra = host.count(".") - rd.count(".") if rd else 0
        if extra >= SUBDOMAIN_DEPTH_FLAG:
            deep.append(host)
    if deep:
        _emit(result, "URL_MANY_SUBDOMAINS", "Deeply nested subdomains",
              f"Host(s) stuff many subdomain labels in front of the real domain "
              f"to look legitimate: {_sample(deep)}.",
              points=POINTS_MANY_SUBDOMAINS)
