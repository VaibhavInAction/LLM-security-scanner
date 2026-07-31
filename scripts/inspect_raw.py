"""
Inspect the downloaded raw datasets.

Run:  python scripts/inspect_raw.py

Prints each file's columns, row count, label distribution, and a few sample
rows. This is the "spot-check before you trust it" step from DATA.md section 3.

Published reviews have found mislabeled rows, duplicates, and benign text
labeled as attacks across popular prompt-injection datasets. If your ground
truth is wrong, every metric you compute later is wrong in a way no amount of
good code will reveal.
"""

import csv
import json
from collections import Counter
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw"
WIDTH = 96


def preview(value, limit: int = 110) -> str:
    """Render any cell value as a single readable line."""
    s = str(value).replace("\n", " ").replace("\r", " ")
    s = " ".join(s.split())
    return s[:limit] + ("..." if len(s) > limit else "")


def inspect_jsonl(path: Path) -> None:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        print("  (empty)")
        return

    cols = list(rows[0].keys())
    print(f"  rows: {len(rows)}   columns: {cols}")

    # Label distribution, if there is anything that looks like a label.
    for col in cols:
        values = [r.get(col) for r in rows]
        distinct = {v for v in values if isinstance(v, (int, bool, str)) and not isinstance(v, bool) or isinstance(v, bool)}
        if 0 < len(set(map(str, values))) <= 6 and col.lower() in {"label", "labels", "is_injection", "type", "category", "goal_type"}:
            dist = Counter(map(str, values))
            print(f"  {col} distribution: {dict(dist)}")

    # Duplicate check on the longest text-looking column.
    text_col = max(cols, key=lambda c: sum(len(str(r.get(c, ""))) for r in rows))
    texts = [str(r.get(text_col, "")) for r in rows]
    dupes = len(texts) - len(set(texts))
    lengths = sorted(len(t) for t in texts)
    print(f"  text column: '{text_col}'   duplicates: {dupes}   "
          f"len min/median/max: {lengths[0]}/{lengths[len(lengths)//2]}/{lengths[-1]}")

    print("  samples:")
    step = max(1, len(rows) // 3)
    for r in rows[::step][:3]:
        for c in cols:
            print(f"     {c}: {preview(r[c])}")
        print()


def inspect_csv(path: Path) -> None:
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print("  (empty)")
        return
    print(f"  rows: {len(rows)}   columns: {list(rows[0].keys())}")
    print("  samples:")
    step = max(1, len(rows) // 3)
    for r in rows[::step][:3]:
        for c, v in r.items():
            print(f"     {c}: {preview(v)}")
        print()


def main() -> None:
    files = sorted(RAW.glob("*.jsonl")) + sorted(RAW.glob("*.csv"))
    if not files:
        print(f"No files in {RAW}. Run scripts/fetch_datasets.py first.")
        return

    total = 0
    for path in files:
        print("=" * WIDTH)
        print(path.name)
        print("=" * WIDTH)
        if path.suffix == ".jsonl":
            n = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
            inspect_jsonl(path)
        else:
            with open(path, encoding="utf-8", newline="") as f:
                n = sum(1 for _ in csv.DictReader(f))
            inspect_csv(path)
        total += n

    print("=" * WIDTH)
    print(f"{len(files)} files, {total} rows total")
    print("\nNow read some rows YOURSELF. Look for:")
    print("  - rows labeled 'attack' that are clearly harmless")
    print("  - rows labeled 'benign' that are clearly attacks")
    print("  - near-duplicates that would inflate your metrics")
    print("  - anything in a language or format you did not expect")


if __name__ == "__main__":
    main()
