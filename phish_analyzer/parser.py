

from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path

from .domains import extract_domain
from .models import EmailAddress, ParsedEmail

# Bare URLs sitting in plain-text bodies.
_URL_RE = re.compile(r"""https?://[^\s<>"'\)\]}]+""", re.IGNORECASE)


# HTML handling

class _HTMLExtractor(HTMLParser):
    """Collect visible text and clickable link targets from an HTML body."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_chunks: list[str] = []
        self.links: list[str] = []
        self.anchors: list[tuple[str, str]] = []  
        self._skip = 0  
        self._a_href: str | None = None       
        self._a_text: list[str] = []          

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        attr = dict(attrs)
        
        for key in ("href", "action"):
            val = attr.get(key)
            if val and val.strip().lower().startswith(("http://", "https://")):
                self.links.append(val.strip())
       
        if tag == "a":
            href = (attr.get("href") or "").strip()
            self._a_href = href or None
            self._a_text = []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._a_href is not None:
            self.anchors.append((" ".join(self._a_text).strip(), self._a_href))
            self._a_href = None
            self._a_text = []

    def handle_data(self, data: str) -> None:
        if not self._skip and data.strip():
            self.text_chunks.append(data.strip())
            if self._a_href is not None:
                self._a_text.append(data.strip())

    @property
    def text(self) -> str:
        return " ".join(self.text_chunks)


def _html_to_text_and_links(html: str) -> tuple[str, list[str], list[tuple[str, str]]]:
    extractor = _HTMLExtractor()
    try:
        extractor.feed(html)
    except Exception:  
        pass
    return extractor.text, extractor.links, extractor.anchors



# Header / address helpers

def _safe_header(msg, name: str):
   
    try:
        value = msg[name]
        if value is not None:
            getattr(value, "addresses", None) 
        return value
    except Exception:  
        for key, raw in getattr(msg, "_headers", []):
            if key.lower() == name.lower():
                return str(raw)
        return None


def _to_address(value) -> EmailAddress | None:
    
    if value is None:
        return None

    addresses = getattr(value, "addresses", None)
    if addresses:
        primary = next((a for a in addresses if a.domain), addresses[0])
        name_parts: list[str] = []
        for a in addresses:
            if a is primary:
                fragment = a.display_name
            elif a.domain:
                continue  
            else:
                
                fragment = a.display_name or a.addr_spec
            if fragment and fragment.strip():
                name_parts.append(fragment.strip())
        addr = (primary.addr_spec or "").strip()
        if addr == "<>":
            addr = ""
        return EmailAddress(
            display=" ".join(name_parts).strip(),
            addr=addr,
            domain=extract_domain(addr),
        )
    
    display, addr = parseaddr(str(value))
    return EmailAddress(display=display.strip(), addr=addr.strip(), domain=extract_domain(addr))


def _all_addresses(value) -> list[EmailAddress]:
    if value is None:
        return []
    addresses = getattr(value, "addresses", None)
    out: list[EmailAddress] = []
    if addresses:
        for a in addresses:
            addr = (a.addr_spec or "").strip()
            out.append(EmailAddress(display=(a.display_name or "").strip(),
                                    addr=addr, domain=extract_domain(addr)))
        return out
    one = _to_address(value)
    return [one] if one else []


def _get_part_text(part) -> str:
    """Decode a single MIME part to text, surviving bad charsets/encodings."""
    try:
        content = part.get_content()
        return content if isinstance(content, str) else content.decode("utf-8", "replace")
    except Exception:  
        payload = part.get_payload(decode=True)
        if payload is None:
            raw = part.get_payload()
            return raw if isinstance(raw, str) else ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, "replace")
        except LookupError:
            return payload.decode("utf-8", "replace")


def _extract_bodies(msg) -> tuple[str, str]:
    """Return (plain_text, html) concatenated across all non-attachment parts."""
    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if (part.get_content_disposition() or "") == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            text_parts.append(_get_part_text(part))
        elif ctype == "text/html":
            html_parts.append(_get_part_text(part))
    return "\n".join(text_parts), "\n".join(html_parts)





def parse_bytes(raw: bytes, source: str = "") -> ParsedEmail:
    """Parse raw message bytes into a :class:`ParsedEmail`."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    body_text, body_html = _extract_bodies(msg)
    html_text, html_links, anchors = _html_to_text_and_links(body_html)

   
    links: list[str] = list(html_links)
    links += _URL_RE.findall(body_text)
 
    seen: set[str] = set()
    links = [u for u in links if not (u in seen or seen.add(u))]

    message_id = (str(msg["Message-ID"]).strip() if msg["Message-ID"] else "")
    mid_domain = extract_domain(message_id.strip("<>")) if "@" in message_id else ""

    
    headers: dict[str, list[str]] = {}
    for key, val in getattr(msg, "_headers", []):
        headers.setdefault(key.lower(), []).append(str(val))

    return ParsedEmail(
        source=source,
        subject=str(msg["Subject"]) if msg["Subject"] else "",
        date=str(msg["Date"]) if msg["Date"] else "",
        from_addr=_to_address(_safe_header(msg, "From")),
        to=_all_addresses(_safe_header(msg, "To")),
        reply_to=_to_address(_safe_header(msg, "Reply-To")),
        return_path=_to_address(_safe_header(msg, "Return-Path")),
        sender=_to_address(_safe_header(msg, "Sender")),
        message_id=message_id,
        message_id_domain=mid_domain,
        received=[str(v) for v in msg.get_all("Received", [])],
        auth_results=[str(v) for v in msg.get_all("Authentication-Results", [])],
        received_spf=" ".join(str(v) for v in msg.get_all("Received-SPF", [])),
        body_text=body_text or html_text,   
        body_html=body_html,
        links=links,
        anchors=anchors,
        headers=headers,
    )


def parse_file(path: str | Path) -> ParsedEmail:
    """Parse an ``.eml`` (or raw message) file into a :class:`ParsedEmail`."""
    path = Path(path)
    return parse_bytes(path.read_bytes(), source=str(path))
