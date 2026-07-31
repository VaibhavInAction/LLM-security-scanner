"""
Command-line interface to the scanner.

Usage:
    python -m llm_scanner.cli "some text to check"
    python -m llm_scanner.cli --file suspicious_email.txt
    python -m llm_scanner.cli "some text" --json
"""

import argparse
import sys

from .models import Risk
from .scanner import scan


def read_input(args: argparse.Namespace) -> str:
    if args.file:
        # encoding="utf-8" is required on Windows -- the default (cp1252)
        # would silently corrupt the non-ASCII text this scanner looks for.
        with open(args.file, encoding="utf-8") as f:
            return f.read()
    if args.text:
        return args.text
    print("error: provide text as an argument, or use --file", file=sys.stderr)
    sys.exit(1)


def print_human(risk: Risk) -> None:
    print(f"score: {risk.score:.2f}   level: {risk.level.value.upper()}")
    if not risk.detections:
        print("no findings")
        return
    print(f"\n{len(risk.detections)} finding(s):")
    for finding in risk.detections:
        print(f"  [{finding.category.value}] score={finding.score:.2f}  {finding.reason}")
        print(f"      matched: {finding.evidence!r}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan text for LLM security risks.")
    parser.add_argument("text", nargs="?", help="text to scan")
    parser.add_argument("--file", help="read text from a file instead of the argument")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args()

    risk = scan(read_input(args))

    if args.json:
        print(risk.model_dump_json(indent=2))
    else:
        print_human(risk)


if __name__ == "__main__":
    main()
