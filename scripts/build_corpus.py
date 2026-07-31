"""
Build the real benchmark corpus, combining two kinds of source:

  - Automated, sampled from data/raw/ (see scripts/fetch_datasets.py and
    DATA.md section 6b's audit): Gandalf -> prompt_injection; JailbreakBench
    harmful + AdvBench -> jailbreak; Dolly + Alpaca -> ordinary benign.
  - Hand-authored or generated, read from the seed_*.jsonl files in
    benchmark/data/: hard negatives, jailbreak-framed examples,
    indirect_attack, unsafe_output, secret_leakage (the last one's seed file
    is produced by scripts/generate_secrets.py -- run that first).

Every source ends up going through make_row(), so there's one place that
owns the row schema and one place that assigns a row's split.

Run:  python scripts/build_corpus.py
"""

import hashlib
import json
import random
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw"
OUT = Path(__file__).resolve().parent.parent / "llm_scanner" / "benchmark" / "data"

SEED = 20260729  # fixed, so re-running this script reproduces the same corpus
TEST_FRACTION = 0.2  # -> 1 in 5 rows land in test, by id hash (see split_for_id)


def load_jsonl(filename: str) -> list[dict]:
    rows = []
    for line in (RAW / filename).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def load_seed(filename: str) -> list[dict]:
    """Read a hand-authored seed_*.jsonl file from benchmark/data/ itself.

    Seed files hold only {text, category, technique} -- everything else
    (id, label, source, licence, split) is filled in here, same as every
    other row, so there's one place that owns the row schema.
    """
    rows = []
    for line in (OUT / filename).read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def split_for_id(id_: str) -> str:
    """A row's split depends ONLY on its own id, never on what else is in
    the corpus. The old approach (shuffle the whole list, slice 20%) meant
    adding a single new row reassigned every existing row's split -- fine by
    luck while the corpus was static, a silent correctness bug the moment it
    grows (DATA.md 5 plans growth to 300/300)."""
    digest = hashlib.sha256(id_.encode("utf-8")).hexdigest()
    buckets = round(1 / TEST_FRACTION)
    return "test" if int(digest, 16) % buckets == 0 else "train"


def make_row(id_, text, label, category, technique, source, licence) -> dict:
    return {
        "id": id_,
        "text": text,
        "label": label,
        "category": category,
        "technique": technique,
        "source": source,
        "licence": licence,
        "split": split_for_id(id_),
    }


def build_attacks(rng: random.Random) -> list[dict]:
    rows = []

    gandalf = (
        load_jsonl("gandalf_ignore_train.jsonl")
        + load_jsonl("gandalf_ignore_val.jsonl")
        + load_jsonl("gandalf_ignore_test.jsonl")
    )
    sample = rng.sample(gandalf, min(30, len(gandalf)))
    for i, row in enumerate(sample):
        rows.append(make_row(
            f"atk-inj-{i:03d}", row["text"], "attack", "prompt_injection",
            "instruction_override", "Lakera/gandalf_ignore_instructions", "MIT",
        ))

    jbb = load_jsonl("jbb_harmful.jsonl")
    sample = rng.sample(jbb, min(13, len(jbb)))
    for i, row in enumerate(sample):
        rows.append(make_row(
            f"atk-jb-{i:03d}", row["Goal"], "attack", "jailbreak",
            "bare_harmful_request", "JailbreakBench/JBB-Behaviors", "MIT",
        ))

    advbench = load_jsonl("advbench_harmful_behaviors.jsonl") if (RAW / "advbench_harmful_behaviors.jsonl").exists() else None
    if advbench is None:
        import csv
        with open(RAW / "advbench_harmful_behaviors.csv", encoding="utf-8", newline="") as f:
            advbench = list(csv.DictReader(f))
    sample = rng.sample(advbench, min(12, len(advbench)))
    for i, row in enumerate(sample):
        rows.append(make_row(
            f"atk-adv-{i:03d}", row["goal"], "attack", "jailbreak",
            "bare_harmful_request", "llm-attacks/advbench", "MIT",
        ))

    rows += build_jailbreak_framed()
    rows += build_indirect_attack()
    rows += build_unsafe_output()
    rows += build_secret_leakage()

    return rows


def build_jailbreak_framed() -> list[dict]:
    """Persona-override / DAN-style attacks -- the kind jailbreak.yaml actually
    targets. The automated sources above are bare harmful requests with no
    such framing (see PLAN.md section 13); this is what gives jailbreak.yaml
    a fair test."""
    seed = load_seed("seed_jailbreak_framed.jsonl")
    return [
        make_row(f"atk-jbframed-{i:03d}", row["text"], "attack", row["category"],
                  row["technique"], "handwritten", "n/a")
        for i, row in enumerate(seed)
    ]


def build_indirect_attack() -> list[dict]:
    """Instructions addressed to an AI reader, embedded in otherwise-benign
    documents/emails/pages -- DATA.md section 3."""
    seed = load_seed("seed_indirect_attack.jsonl")
    return [
        make_row(f"atk-ind-{i:03d}", row["text"], "attack", row["category"],
                  row["technique"], "handwritten", "n/a")
        for i, row in enumerate(seed)
    ]


def build_unsafe_output() -> list[dict]:
    """Representative payloads across the major output-handling vulnerability
    classes -- standard textbook payloads, not original prose, so attributed
    to their usual source rather than "handwritten"."""
    seed = load_seed("seed_unsafe_output.jsonl")
    return [
        make_row(f"atk-uo-{i:03d}", row["text"], "attack", row["category"],
                  row["technique"], "PayloadsAllTheThings", "MIT")
        for i, row in enumerate(seed)
    ]


def build_secret_leakage() -> list[dict]:
    """Synthetic fake-but-format-correct secrets -- see scripts/generate_secrets.py.
    Run that script first to (re)produce seed_secret_leakage.jsonl."""
    seed = load_seed("seed_secret_leakage.jsonl")
    return [
        make_row(f"atk-sec-{i:03d}", row["text"], "attack", row["category"],
                  row["technique"], "synthetic_generator", "n/a")
        for i, row in enumerate(seed)
    ]


def build_benign(rng: random.Random) -> list[dict]:
    # NOTE: JailbreakBench's "benign" split is deliberately excluded. It means
    # "topically similar to a harmful prompt but not a policy violation," not
    # "ordinary user traffic" -- spot-checking it turned up phishing-email and
    # NSFW-content requests. Same lesson as the deepset audit in DATA.md: a
    # label is only meaningful relative to what the dataset measures.
    rows = []

    dolly = load_jsonl("dolly.jsonl")
    sample = rng.sample(dolly, min(30, len(dolly)))
    for i, row in enumerate(sample):
        rows.append(make_row(
            f"ben-dolly-{i:03d}", row["instruction"], "benign", None,
            "ordinary_traffic", "databricks/databricks-dolly-15k", "CC-BY-SA-3.0",
        ))

    alpaca = load_jsonl("alpaca.jsonl")
    sample = rng.sample(alpaca, min(30, len(alpaca)))
    for i, row in enumerate(sample):
        rows.append(make_row(
            f"ben-alpaca-{i:03d}", row["instruction"], "benign", None,
            "ordinary_traffic", "tatsu-lab/alpaca", "CC-BY-NC-4.0",
        ))

    rows += build_hard_negatives()

    return rows


def build_hard_negatives() -> list[dict]:
    """Benign text that LOOKS like an attack -- DATA.md section 4b.

    No sampling here: every hard negative was deliberately chosen, so all of
    them go in, in file order.
    """
    seed = load_seed("seed_hard_negatives.jsonl")
    return [
        make_row(f"ben-hn-{i:03d}", row["text"], "benign", None,
                  row["technique"], "handwritten", "n/a")
        for i, row in enumerate(seed)
    ]


def main() -> None:
    rng = random.Random(SEED)

    attacks = build_attacks(rng)
    benign = build_benign(rng)

    OUT.mkdir(parents=True, exist_ok=True)
    for filename, rows in (("attacks.jsonl", attacks), ("benign.jsonl", benign)):
        with open(OUT / filename, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"wrote {len(rows):>3} rows -> {filename}")

    print("\nPhase 1 corpus complete (see PLAN.md section 14).")


if __name__ == "__main__":
    main()
