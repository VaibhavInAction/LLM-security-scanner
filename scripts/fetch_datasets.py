"""
Download the raw source datasets into data/raw/.

Run once:  python scripts/fetch_datasets.py

WHY NO `datasets` LIBRARY
-------------------------
The obvious way to do this is `pip install datasets`, but that pulls in pyarrow,
whose native DLL is blocked by Windows Application Control on this machine:

    ImportError: DLL load failed while importing lib:
    An Application Control policy has blocked this file.

Rather than weaken a machine security policy, this script uses HuggingFace's
public REST API (datasets-server) and Python's standard library only. No pip
install is required at all, and the whole download is a few thousand JSON rows.

That turns out to be the better engineering choice anyway: this project's whole
premise is having no heavy runtime dependencies.

This script ONLY downloads and saves raw rows. Converting them to the scanner's
row schema happens later, in one import script per source, after models.py
exists. Keeping the two steps separate means a schema change never forces a
re-download.

No API key is needed. Every source here is public.
"""

import csv
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw"
RAW.mkdir(parents=True, exist_ok=True)

API = "https://datasets-server.huggingface.co/rows"
PAGE = 100          # the API's maximum rows per request
PAUSE = 0.2         # be polite to a free public endpoint


def save_jsonl(rows: list[dict], filename: str) -> None:
    """Write rows to data/raw/<filename>, one JSON object per line.

    encoding="utf-8" is NOT optional on Windows. The default there is cp1252,
    which silently mangles exactly the non-ASCII characters (homoglyphs,
    zero-width spaces) that this project exists to detect.
    """
    path = RAW / filename
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"    saved {len(rows):>5} rows -> data/raw/{filename}")


def get_json(url: str, attempts: int = 4) -> dict:
    """GET a URL and parse JSON, retrying on transient server errors.

    The datasets-server is a free public service and returns a 500 or 503 now
    and then for no reason. Without this retry, a healthy dataset gets recorded
    as "SKIPPED" and you go hunting for a problem that does not exist.
    Client errors (401 gated, 404 renamed) are real and raise immediately.
    """
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == attempts:
                raise
            wait = 2 ** attempt          # 2s, 4s, 8s
            print(f"    HTTP {e.code}, retrying in {wait}s "
                  f"(attempt {attempt}/{attempts - 1})")
            time.sleep(wait)
        except urllib.error.URLError as e:
            if attempt == attempts:
                raise
            print(f"    network error, retrying: {e.reason}")
            time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


def fetch_rows(dataset: str, config: str, split: str, max_rows: int) -> list[dict]:
    """Page through the datasets-server API and return up to max_rows rows."""
    out: list[dict] = []
    offset = 0
    while len(out) < max_rows:
        length = min(PAGE, max_rows - len(out))
        url = (
            f"{API}?dataset={urllib.parse.quote(dataset, safe='')}"
            f"&config={urllib.parse.quote(config)}"
            f"&split={urllib.parse.quote(split)}"
            f"&offset={offset}&length={length}"
        )
        payload = get_json(url)

        batch = [item["row"] for item in payload.get("rows", [])]
        if not batch:
            break                      # split is shorter than max_rows
        out.extend(batch)
        offset += len(batch)

        total = payload.get("num_rows_total")
        if total is not None and offset >= total:
            break                      # reached the end of the split
        time.sleep(PAUSE)
    return out


# ---------------------------------------------------------------------------
# What to download.
#   (dataset, config, split, max_rows, output filename)
# Caps exist because the corpus only needs a few hundred rows -- see DATA.md
# section 5. A large pool to sample from is useful; 52,000 rows of Alpaca is not.
# ---------------------------------------------------------------------------
SOURCES = [
    # --- attacks -----------------------------------------------------------
    ("deepset/prompt-injections", "default", "train", 1000, "deepset_injections_train.jsonl"),
    ("deepset/prompt-injections", "default", "test", 1000, "deepset_injections_test.jsonl"),
    ("Lakera/gandalf_ignore_instructions", "default", "train", 1000, "gandalf_ignore_train.jsonl"),
    ("Lakera/gandalf_ignore_instructions", "default", "validation", 200, "gandalf_ignore_val.jsonl"),
    ("Lakera/gandalf_ignore_instructions", "default", "test", 200, "gandalf_ignore_test.jsonl"),
    ("Lakera/gandalf_summarization", "default", "train", 500, "gandalf_summarization.jsonl"),
    ("reshabhs/SPML_Chatbot_Prompt_Injection", "default", "train", 1000, "spml_injection.jsonl"),
    ("JailbreakBench/JBB-Behaviors", "behaviors", "harmful", 200, "jbb_harmful.jsonl"),
    # --- benign ------------------------------------------------------------
    ("JailbreakBench/JBB-Behaviors", "behaviors", "benign", 200, "jbb_benign.jsonl"),
    ("databricks/databricks-dolly-15k", "default", "train", 500, "dolly.jsonl"),
    ("tatsu-lab/alpaca", "default", "train", 500, "alpaca.jsonl"),
]

# Gated -- need a free HuggingFace account and `huggingface-cli login`:
#   Mindgard/evaded-prompt-injection-and-jailbreak-samples
#   hackaprompt/hackaprompt-dataset   (also unlabeled -- see DATA.md)

DIRECT_FILES = [
    (
        "AdvBench harmful behaviors",
        "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv",
        "advbench_harmful_behaviors.csv",
    ),
]


def fetch_all() -> None:
    print("=== HuggingFace datasets (REST API, no dependencies) ===")
    ok = failed = 0
    for dataset, config, split, cap, out in SOURCES:
        print(f"\n  {dataset} [{config}/{split}]")
        try:
            rows = fetch_rows(dataset, config, split, cap)
            save_jsonl(rows, out)
            ok += 1
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = json.loads(e.read().decode()).get("error", "")
            except Exception:
                pass
            print(f"    SKIPPED: HTTP {e.code} {detail}")
            print(f"    -> https://huggingface.co/datasets/{dataset}")
            failed += 1
        except Exception as e:
            print(f"    SKIPPED: {type(e).__name__}: {e}")
            failed += 1

    print("\n=== Direct downloads ===")
    for name, url, out in DIRECT_FILES:
        print(f"\n  {name}")
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                data = resp.read().decode("utf-8")
            (RAW / out).write_text(data, encoding="utf-8")
            n = sum(1 for _ in csv.reader(io.StringIO(data))) - 1
            print(f"    saved {n:>5} rows -> data/raw/{out}")
            ok += 1
        except Exception as e:
            print(f"    SKIPPED: {type(e).__name__}: {e}")
            print(f"    -> {url}")
            failed += 1

    print(f"\n{ok} succeeded, {failed} skipped")


MANUAL = """
=== Still to collect by hand ===

unsafe_output payloads  (~40 rows, hand-picked)
  SecLists              https://github.com/danielmiessler/SecLists
  PayloadsAllTheThings  https://github.com/swisskyrepo/PayloadsAllTheThings

  Do NOT clone these -- SecLists alone is over a gigabyte. Browse to the XSS,
  SQLi, and command-injection folders on the web, pick ~40 representative
  payloads, and paste them into data/raw/manual_unsafe_output.txt (one per line).
  Forty good payloads beat forty thousand near-duplicates.

secret_leakage samples  (~10 rows, generated)
  Write scripts/gen_secrets.py to emit fake-but-format-correct AWS keys,
  sk- tokens, JWTs, and private-key headers. Use Faker for PII.
  NEVER use a real key -- not even an expired one, not even your own.

hard negatives  (~40 rows, handwritten)
  The highest-value work of week 1. Nothing you download replaces these.
  See DATA.md section 4b for the ten trap families to cover.
"""


if __name__ == "__main__":
    fetch_all()
    print(MANUAL)
    print(f"Raw data is in: {RAW}")
    print("\nNext: open 2-3 of these files and read 20 random rows by hand before")
    print("trusting any of them. Published reviews have found mislabeled and")
    print("duplicated rows in popular prompt-injection datasets.")
