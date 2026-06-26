
from __future__ import annotations

import re
from urllib.parse import urlsplit

# Common two-label public suffixes (country-code second-level domains).
_MULTI_SUFFIXES: frozenset[str] = frozenset(
    {
        # United Kingdom
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
        # Brazil
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        # Australia
        "com.au", "net.au", "org.au", "gov.au", "edu.au", "id.au",
        # Japan
        "co.jp", "or.jp", "ne.jp", "go.jp", "ac.jp",
        # India
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        # Korea
        "co.kr", "or.kr", "ne.kr", "go.kr",
        # Generic .com.* / .co.* country variants
        "com.mx", "com.ar", "com.co", "com.tr", "com.cn", "com.hk", "com.sg",
        "com.my", "com.tw", "com.ph", "com.vn", "com.pk", "com.sa", "com.eg",
        "com.ng", "com.pl", "com.ua", "com.ru", "com.es", "com.pt", "com.gr",
        "co.za", "co.nz", "co.id", "co.th", "co.il", "co.ke",
    }
)


def extract_domain(addr: str) -> str:
    
    if not addr or "@" not in addr:
        return ""
    domain = addr.rsplit("@", 1)[1]
    return domain.strip().strip("<>").rstrip(".").lower()


def hostname_of(url_or_host: str) -> str:
    
    if not url_or_host:
        return ""
    value = url_or_host.strip()
    if "//" not in value:
        value = "//" + value          # let urlsplit treat it as a netloc
    host = urlsplit(value).hostname or ""
    return host.rstrip(".").lower()


def registered_domain(domain: str) -> str:
    
    if not domain:
        return ""
    domain = domain.strip().strip(".").lower()
    # If we were handed a URL or address, normalise to a bare host first.
    if "//" in domain or "@" in domain or "/" in domain:
        domain = hostname_of(domain) or extract_domain(domain) or domain
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# Free / consumer webmail providers. A *branded* sender (a bank, a company)
# whose Reply-To lands on one of these is a classic phishing tell.
FREEMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com", "googlemail.com",
        "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "ymail.com", "rocketmail.com",
        "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com", "msn.com",
        "aol.com", "aim.com",
        "icloud.com", "me.com", "mac.com",
        "gmx.com", "gmx.net", "gmx.de", "mail.com", "email.com",
        "proton.me", "protonmail.com", "tutanota.com", "tuta.io",
        "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "inbox.ru",
        "163.com", "126.com", "qq.com", "foxmail.com",
    }
)


def is_freemail(domain: str) -> bool:
    
    if not domain:
        return False
    domain = domain.lower()
    return domain in FREEMAIL_DOMAINS or registered_domain(domain) in FREEMAIL_DOMAINS


 
# Generic host primitives (used by the link analyzer)
 
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_ip_host(host: str) -> bool:
    
    if not host:
        return False
    host = host.strip().strip("[]").lower()
    if _IPV4_RE.match(host):
        return all(0 <= int(o) <= 255 for o in host.split("."))
    return ":" in host  # IPv6 literal (urlsplit only yields this for [..] hosts)


def levenshtein(a: str, b: str, max_distance: int | None = None) -> int:
    
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if abs(len(a) - len(b)) > (max_distance if max_distance is not None else len(a) + len(b)):
        return (max_distance + 1) if max_distance is not None else abs(len(a) - len(b))

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(
                previous[j] + 1,        # deletion
                current[j - 1] + 1,     # insertion
                previous[j - 1] + cost,  # substitution
            ))
        if max_distance is not None and min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]
