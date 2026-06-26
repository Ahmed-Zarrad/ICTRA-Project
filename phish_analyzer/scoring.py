

from __future__ import annotations

from .models import RISK_BANDS, ModuleResult, OverallResult, ParsedEmail


MODULE_WEIGHTS: dict[str, float] = {
    "header": 0.40,
    "link": 0.35,
    "language": 0.25,
}


PEAK_WEIGHT = 0.85
AVG_WEIGHT = 0.50


BAND_THRESHOLDS: dict[str, int] = {
    "low": 25,       
    "medium": 50,    
    "high": 75,      
    
}


def band_for_score(score: int) -> str:
    """Map a 0-100 overall score to a :data:`RISK_BANDS` label."""
    if score < BAND_THRESHOLDS["low"]:
        return "low"
    if score < BAND_THRESHOLDS["medium"]:
        return "medium"
    if score < BAND_THRESHOLDS["high"]:
        return "high"
    return "critical"


def combine(email: ParsedEmail, modules: list[ModuleResult]) -> OverallResult:
    """Combine module results into a single :class:`OverallResult`."""
    by_name = {m.name: m for m in modules}

    weighted_sum = 0.0
    weight_total = 0.0
    for name, weight in MODULE_WEIGHTS.items():
        module = by_name.get(name)
        if module is None:
            continue
        weighted_sum += weight * module.score
        weight_total += weight

    weighted_avg = (weighted_sum / weight_total) if weight_total else 0.0
    peak = max((m.score for m in modules), default=0)

    overall = PEAK_WEIGHT * peak + AVG_WEIGHT * weighted_avg
    score = max(0, min(100, round(overall)))

    return OverallResult(
        email=email,
        score=score,
        band=band_for_score(score),
        modules=list(modules),
        weights=dict(MODULE_WEIGHTS),
    )
