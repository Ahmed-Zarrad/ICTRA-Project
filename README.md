# Phishing Email Risk Analyzer

A **rule-based** (non-ML) phishing-email risk analyzer written in pure Python 3
with **no third-party dependencies** (standard library only). It reads an email
file, scores its phishing risk from three independent angles, combines them into
a single weighted risk rating, and produces an explainable HTML report.

Built for a university risk-assessment course. The design priority is
**explainability and a low false-positive rate**: every point in the score is
traceable to a concrete, human-readable finding, and the analyzer is carefully
tuned so it does *not* flag legitimate mail.

---

## How it works

```
 raw .eml ──▶ parser ──▶ ParsedEmail ──┬─▶ header_analysis   ─▶ ModuleResult ┐
                                        ├─▶ link_analysis     ─▶ ModuleResult ┼─▶ scoring ─▶ OverallResult ─▶ report (HTML)
                                        └─▶ language_analysis ─▶ ModuleResult ┘
```

Each analysis module returns a `ModuleResult` with a 0–100 sub-score and a list
of explainable `Finding`s (code, title, evidence, points). The combiner folds
the three sub-scores into one 0–100 risk score and a band:
**low / medium / high / critical**.

### 1. Header analysis (`header_analysis.py`)
- **Authentication**: parses `Authentication-Results` / `Received-SPF` for
  SPF, DKIM, DMARC and composite-auth verdicts; scores results that are
  *present and failing*.
- **Identity alignment**: Return-Path, Reply-To and DKIM `d=` vs the visible
  `From` domain (envelope/signature alignment).
- **Sender sanity**: empty/forged `From`, a brand name in the display field the
  real domain doesn't back up, an organisation/notification name sent from free
  webmail, Reply-To diverted to free webmail.

### 2. Link analysis (`link_analysis.py`)
- **Look-alike domains** via Levenshtein edit distance + homoglyph folding
  (`paypa1.com`, `amaz0n.com`), with length guards so short brands don't alias
  to noise.
- **Brand misuse**: a trusted brand name planted in a domain owned by someone
  else (`paypal.secure-login.ru`).
- **Deceptive destinations**: raw-IP hosts, the `user@host` credential trick,
  punycode/IDN homographs.
- **Display deception**: anchor text that names a different domain than the link
  actually opens.
- **Weak signals**: URL shorteners, abuse-prone TLDs, deep subdomain nesting.

### 3. Language analysis (`language_analysis.py`)
- Phrase-based scoring of manufactured **urgency**, account **threats**,
  **credential** lures, **sensitive-info** requests, and **reward** bait, plus
  stylistic tells (ALL-CAPS subject, excessive punctuation).
- Multilingual coverage (English + Portuguese / Spanish / German) because the
  phishing corpus is heavily non-English.
- Per-category caps and a synergy bonus for stacking multiple tactics, so a
  single innocent keyword can't run the score up.

### 4. Scoring (`scoring.py`)
`overall = 0.85 · max(modules) + 0.50 · weighted_average(modules)` (clamped
0–100). The **peak** term gives sensitivity to a single decisive angle; the
**average** term rewards corroboration and keeps legitimate mail — which scores
low on *all* angles — safely low.

---

## Fairness constraints (why it doesn't over-flag legitimate mail)

The legitimate control set (SpamAssassin ham, Enron) is from 1999–2002 and
predates modern email authentication. Several rules exist specifically to avoid
systematically punishing legitimate mail:

- **Absent SPF/DKIM/DMARC adds 0 points.** Only auth headers that *exist and
  fail* contribute risk. (Penalising absence would flag every pre-2004 email.)
- **Message-ID domain ≠ From is informational (0 points).** Legitimate MTAs and
  ESPs routinely generate their own Message-IDs.
- **Return-Path / Reply-To mismatches are weak and suppressed for list/bulk
  mail.** Mailing lists and ESPs legitimately rewrite the envelope sender and
  point replies at a list address.

These carve-outs are the difference between a ~0.2% and a ~15% false-positive
rate on the control set.

---

## Usage

No installation required — pure standard library.

### Command line

```bash
# Analyse one email (prints an explainable summary)
python -m phish_analyzer suspicious.eml

# Analyse several
python -m phish_analyzer emails/*.eml

# Also write an HTML report and open it
python -m phish_analyzer suspicious.eml --html report.html --open
```

### As a library

```python
from phish_analyzer.pipeline import analyze_file
from phish_analyzer import report

result = analyze_file("suspicious.eml")
print(result.band, result.score)          # e.g. "critical" 88
for f in result.findings:
    print(f.severity, f.points, f.title)

report.write_html(result, "report.html")
```

---

## Datasets & evaluation

- **Phishing**: [Phishing Pot](https://github.com/rf-peixoto/phishing_pot)
  (`phishing_pot-main/email/*.eml`) — real phishing with full headers.
- **Legitimate (control)**: SpamAssassin `easy_ham` + `hard_ham`.

Run the evaluation harness (confusion matrix + metrics):

```bash
python scripts/evaluate.py                 # full run
python scripts/evaluate.py --limit 600     # quick subset
python scripts/evaluate.py --csv out.csv   # dump per-email rows
```

### Results

See [`docs/RESULTS.md`](docs/RESULTS.md) for the full evaluation report. Headline
figures (full corpus, decision boundary = `medium`):

<!-- RESULTS:START -->
| Metric | Value |
|---|---|
| Phishing analysed | 8,608 |
| Legitimate analysed | 2,750 |
| **Detection rate (recall)** | **67.1%** |
| **False-positive rate** | **0.44%** |
| Precision | 99.8% |
| F1 score | 80.2% |

Mean score: phishing **46.1/100**, legitimate **0.8/100**. No legitimate email
reached `high` or `critical`. Raising the decision boundary to `high+` gives a
**0.00%** false-positive rate at 44% recall.
<!-- RESULTS:END -->

---

## Project layout

```
phish_analyzer/
  __init__.py          public API + package docs
  __main__.py          command-line interface
  models.py            shared data structures (ParsedEmail, Finding, ...)
  domains.py           domain/host helpers (eTLD+1, freemail, edit distance)
  parser.py            Module 1 — raw email  -> ParsedEmail
  header_analysis.py   Module 2 — SPF/DKIM/DMARC + spoofing
  link_analysis.py     Module 3 — look-alike domains, IP hosts, anchor tricks
  language_analysis.py Module 4 — urgency/threat/credential wording
  scoring.py           Module 5 — weighted combination -> risk band
  report.py            Module 6 — self-contained HTML report
  pipeline.py          glue: raw email -> OverallResult
scripts/
  demo_header.py       quick visual check of header analysis
  evaluate.py          dataset evaluation (confusion matrix + metrics)
tests/
  test_parser_header.py
  test_link_language_scoring.py
```

Run all tests:

```bash
python tests/test_parser_header.py
python tests/test_link_language_scoring.py
```

---

## Limitations

- Rule-based heuristics, not machine learning: novel patterns outside the rules
  are missed by design.
- The public-suffix logic is a curated heuristic, not the full Public Suffix
  List (correct for the common cases in these datasets).
- Detection is strongest on header/link/wording signals; phishing that is sent
  from a genuinely compromised legitimate account with no coercive wording (e.g.
  abused ESP infrastructure) is the hardest residual case.
```
