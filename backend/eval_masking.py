"""Pomiar warstwy maskowania na przypadkach z tests/datasets/output_guardrail_tests.json.

Dwie liczby dla każdego kanału:
  - przecieki: przypadki z danymi wrażliwymi (oczekiwane REDACT/BLOCK), w których nic nie ukryto,
  - nadgorliwość: przypadki bezpieczne (oczekiwane ALLOW), w których coś ukryto lub zablokowano.

Użycie (z katalogu backend/):
    python eval_masking.py            # sama konfiguracja, typy "judge" są maskowane
    python eval_masking.py --judge    # typy "judge" rozstrzyga sędzia LLM (wywołania modelu)
    python eval_masking.py -v         # dodatkowo lista przypadków rozstrzygniętych inaczej niż oczekiwano
"""
import argparse
import json
from collections import Counter
from pathlib import Path

import pipeline
from security.masking import chatbot_action
from security.pii_judge import judge_entities
from security.common.roles import normalize_role

DATASET = Path(__file__).parent / "tests" / "datasets" / "output_guardrail_tests.json"


def output_action(role: str, text: str) -> str:
    """Co filtr odpowiedzi zrobił z tekstem dla danej roli: ALLOW / REDACT / BLOCK."""
    _, _, stats = pipeline.filter_output(role, text)
    if stats["blocked"]:
        return "BLOCK"
    return "REDACT" if stats["redacted"] else "ALLOW"


def chatbot_masked(role: str, text: str, use_judge: bool) -> int:
    """Ile encji zostałoby zamaskowanych, zanim tekst trafi do chatbota."""
    entities = pipeline._detect(text, None)
    masked = [e for e in entities if chatbot_action(e["type"]) in ("redact", "block")]
    pending = [e for e in entities if chatbot_action(e["type"]) == "judge"]
    if pending and use_judge:
        decisions = judge_entities(role, text, pending)
        masked += [e for e, d in zip(pending, decisions) if d == "mask"]
    else:
        masked += pending
    return len(masked)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--judge", action="store_true", help="użyj sędziego LLM dla typów 'judge'")
    parser.add_argument("-v", "--verbose", action="store_true", help="pokaż przypadki niezgodne z oczekiwaniem")
    args = parser.parse_args()

    cases = json.loads(DATASET.read_text(encoding="utf-8"))
    sensitive = [c for c in cases if c["expected_action"] in ("REDACT", "BLOCK")]
    safe = [c for c in cases if c["expected_action"] == "ALLOW"]

    confusion = Counter()
    out_leaks, out_over, bot_leaks, bot_over, exact = [], [], [], [], 0
    for case in cases:
        role = normalize_role(case["user_role"])
        text = case["raw_llm_output"]
        expected = case["expected_action"]

        actual = output_action(role, text)
        confusion[(expected, actual)] += 1
        exact += expected == actual
        masked = chatbot_masked(role, text, args.judge)

        if expected == "ALLOW":
            if actual != "ALLOW":
                out_over.append(case["id"])
            if masked:
                bot_over.append(case["id"])
        else:
            if actual == "ALLOW":
                out_leaks.append(case["id"])
            if not masked:
                bot_leaks.append(case["id"])

    print(f"Przypadki: {len(cases)} (wrażliwe: {len(sensitive)}, bezpieczne: {len(safe)})")
    print(f"Sędzia LLM: {'tak' if args.judge else 'nie'}\n")
    print("Kanał użytkownika (filtr odpowiedzi wg polityki roli)")
    print(f"  przecieki:    {len(out_leaks)}/{len(sensitive)}")
    print(f"  nadgorliwość: {len(out_over)}/{len(safe)}")
    print(f"  działanie zgodne z oczekiwanym (ALLOW/REDACT/BLOCK): {exact}/{len(cases)}")
    print("  oczekiwane -> faktyczne:")
    for (expected, actual), n in sorted(confusion.items()):
        print(f"    {expected:7} -> {actual:7} {n}")
    print("\nKanał chatbota (maskowanie przed wysłaniem do modelu)")
    print(f"  przecieki:    {len(bot_leaks)}/{len(sensitive)}")
    print(f"  nadgorliwość: {len(bot_over)}/{len(safe)}  (maskowanie odwracalne, nie psuje odpowiedzi)")

    if args.verbose:
        for title, ids in [("Przecieki — kanał użytkownika", out_leaks), ("Nadgorliwość — kanał użytkownika", out_over),
                           ("Przecieki — kanał chatbota", bot_leaks), ("Nadgorliwość — kanał chatbota", bot_over)]:
            print(f"\n{title}: {', '.join(ids) or '-'}")


if __name__ == "__main__":
    main()
