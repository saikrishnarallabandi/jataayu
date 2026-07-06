# ARR submission guide

This paper is formatted for **ACL Rolling Review (ARR)** — the always-open, rolling submission
system for *ACL venues (ACL, EMNLP, NAACL, EACL). Submit anytime; after review you *commit* the
paper to a specific venue or workshop.

## Status: submission-ready
- **Format:** ACL template, `\usepackage[review]{acl}` → anonymized + line-numbered (required for ARR double-blind).
- **Anonymized:** ✓ author is "Anonymous ACL submission"; no "Jataayu"/repo/author identifiers (verified).
- **Limitations section:** ✓ (required by ARR).
- **Ethics Statement:** ✓.
- **Length:** 4 pages incl. references — within the ARR **short-paper** limit (4 pp content, refs/limitations/ethics excluded).
- Compiles with `pdflatex → bibtex → pdflatex ×2`.

## How to submit
1. Go to **https://openreview.net** → the current **ACL Rolling Review** submission cycle
   (cadence is roughly monthly; check https://aclrollingreview.org for the open deadline).
2. Create a submission, upload `injection_lora.pdf` (keep it anonymized — do NOT add author names yet).
3. Suggested area/track: **Resources and Evaluation** or **NLP Applications** (the paper is an
   empirical evaluation study); flag the Ethics/robustness relevance.
4. Fill the **Responsible NLP Research checklist** (done in the OpenReview form, not the PDF):
   datasets are public, no new attack technique, defense-oriented — see the paper's Ethics Statement.
5. After you receive reviews (meta-review + scores), **commit** the paper to a target venue: EMNLP 2026,
   a future TrustNLP, or another *ACL workshop. Fast-track options exist for papers with strong ARR scores.

## At camera-ready (after acceptance)
- Switch `\usepackage[review]{acl}` → `\usepackage[final]{acl}` and add author names/affiliations.

## Reproducibility
Training + eval pipeline: `training/injection_lora/` (see its README). Held-out results:
`eval/results/injection_lora_heldout.json`.
