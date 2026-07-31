# Benchmark corpus

The `.jsonl` files in this directory are **adversarial security test fixtures**.
They contain real and synthetic prompt-injection, jailbreak, and exploit-payload
text, collected and written to measure this project's detectors — see
[DATA.md](../../../DATA.md) and [PLAN.md](../../../PLAN.md) sections 3 and 11.

None of this exists to attack anyone. It exists so the scanner's TPR/FPR numbers
are backed by real, labeled data instead of guesses.

- `attacks.jsonl` / `benign.jsonl` — the built corpus. Regenerate with
  `python scripts/build_corpus.py`; do not hand-edit.
- `seed_*.jsonl` — hand-authored or generated source content, read by
  `build_corpus.py`. This is what to edit.

Every row's `licence` field records where its text came from, since several
sources are third-party datasets being redistributed here under their own
licences (see DATA.md section 7).
