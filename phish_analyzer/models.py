

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional



# Parsed email

@dataclass
class EmailAddress:
    """A single parsed address, e.g. From / Reply-To / Return-Path."""

    display: str = ""   
    addr: str = ""      
    domain: str = ""    

    @property
    def is_empty(self) -> bool:
        """True when there is no actual address (e.g. From: "Facebook" <>)."""
        return not self.addr

    def __str__(self) -> str:
        if self.display and self.addr:
            return f'"{self.display}" <{self.addr}>'
        return self.addr or self.display or "(none)"


@dataclass
class ParsedEmail:
   

    source: str = ""                       # file path or identifier
    subject: str = ""
    date: str = ""

    from_addr: Optional[EmailAddress] = None
    to: list[EmailAddress] = field(default_factory=list)
    reply_to: Optional[EmailAddress] = None
    return_path: Optional[EmailAddress] = None
    sender: Optional[EmailAddress] = None   # the 'Sender:' header, if present

    message_id: str = ""
    message_id_domain: str = ""

    received: list[str] = field(default_factory=list)          # raw Received headers, top first
    auth_results: list[str] = field(default_factory=list)      
    received_spf: str = ""                                     

    body_text: str = ""                    
    body_html: str = ""                    # decoded text/html parts
    links: list[str] = field(default_factory=list)             # URLs found in the body
    
    anchors: list[tuple[str, str]] = field(default_factory=list)

   
    headers: dict[str, list[str]] = field(default_factory=dict)



# Analysis results

SEVERITIES = ("info", "low", "medium", "high")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    

    code: str       
    title: str       
    detail: str     
    severity: str    
    points: int      

    def __post_init__(self) -> None:
        if self.severity not in _SEVERITY_RANK:
            raise ValueError(f"unknown severity {self.severity!r}")


@dataclass
class ModuleResult:
  

    name: str
    score: int = 0                                   # 0..100 risk for this module
    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)  # raw values for the report

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def finalize(self) -> "ModuleResult":
        """Clamp the accumulated points into a 0-100 score and sort findings."""
        self.score = max(0, min(100, self.score))
        self.findings.sort(key=lambda f: _SEVERITY_RANK[f.severity], reverse=True)
        return self


def severity_for_points(points: int) -> str:
    """Map a point contribution to a severity band (tunable thresholds)."""
    if points >= 24:
        return "high"
    if points >= 12:
        return "medium"
    if points >= 4:
        return "low"
    return "info"



# Overall (combined) result

RISK_BANDS = ("low", "medium", "high", "critical")


@dataclass
class OverallResult:
  

    email: ParsedEmail
    score: int                       # 0..100 overall risk
    band: str                        # one of RISK_BANDS
    modules: list[ModuleResult] = field(default_factory=list)
    weights: dict[str, float] = field(default_factory=dict)

    @property
    def findings(self) -> list[Finding]:
        
        out: list[Finding] = []
        for module in self.modules:
            out.extend(module.findings)
        out.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.points), reverse=True)
        return out

    def module(self, name: str) -> Optional[ModuleResult]:
        """Look up one module's result by name (``"header"``/``"link"``/...)."""
        return next((m for m in self.modules if m.name == name), None)
