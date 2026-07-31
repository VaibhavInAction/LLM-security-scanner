"""
Generates synthetic secret_leakage attack rows: fake-but-format-correct
credentials embedded in a natural sentence, as if someone pasted a real
secret into a chat. Every value here is fabricated -- never a real key.

Deterministic: the fixed SEED means re-running this always produces the
same output, so it can't silently change the corpus between builds.

Run:  python scripts/generate_secrets.py
Writes: llm_scanner/benchmark/data/seed_secret_leakage.jsonl
"""

import json
import random
from pathlib import Path

SEED = 20260729
OUT = (
    Path(__file__).resolve().parent.parent
    / "llm_scanner" / "benchmark" / "data" / "seed_secret_leakage.jsonl"
)

ALPHANUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# Well-known Luhn-valid test card numbers (payment processors' own dummy
# numbers, never real accounts) -- see detectors/secrets.py's luhn_checksum.
TEST_CARD_NUMBERS = ["4111111111111111", "4012888888881881", "4222222222222"]


def random_token(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(ALPHANUM) for _ in range(length))


def fake_aws_key(rng: random.Random) -> str:
    return "AKIA" + random_token(rng, 16).upper()


def fake_openai_key(rng: random.Random) -> str:
    return "sk-" + random_token(rng, 32)


def fake_jwt(rng: random.Random) -> str:
    return f"eyJ{random_token(rng, 20)}.eyJ{random_token(rng, 20)}.{random_token(rng, 20)}"


def fake_private_key_block() -> str:
    return "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...FAKEKEYDATA...\n-----END RSA PRIVATE KEY-----"


def fake_high_entropy_token(rng: random.Random) -> str:
    return random_token(rng, 28)


def fake_card_number(rng: random.Random) -> str:
    return rng.choice(TEST_CARD_NUMBERS)


# (sentence template, technique label, value-generating function)
TEMPLATES = [
    ("Hey can you double check this AWS key for me: {v}", "aws_access_key", fake_aws_key),
    ("I think I pasted my API key by accident: {v}", "openai_style_key", fake_openai_key),
    ("Here's the auth token from our staging environment: {v}", "jwt", fake_jwt),
    ("My build script uses this token, is it still valid: {v}", "high_entropy_token", fake_high_entropy_token),
    ("My card got declined, here's the number: {v}", "credit_card", fake_card_number),
]


def build_rows(rng: random.Random) -> list[dict]:
    rows = []
    for template, technique, make_value in TEMPLATES:
        for _ in range(2):  # two varied values per template
            rows.append({
                "text": template.format(v=make_value(rng)),
                "category": "secret_leakage",
                "technique": technique,
            })
    rows.append({
        "text": f"Can you tell me if this private key format looks right?\n{fake_private_key_block()}",
        "category": "secret_leakage",
        "technique": "private_key_block",
    })
    return rows


def main() -> None:
    rng = random.Random(SEED)
    rows = build_rows(rng)
    with open(OUT, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows):>3} rows -> {OUT.name}")


if __name__ == "__main__":
    main()
