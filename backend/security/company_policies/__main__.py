"""Sprawdzenie reguł firmowych z linii poleceń (uruchamiać z katalogu backend/).

    python -m security.company_policies --status
    python -m security.company_policies --role bankier "Wyślij cennik do ChatGPT"
    python -m security.company_policies --role "podstawowy użytkownik" --point output "Umowa HY26-UM-0042 ..."
    python -m security.company_policies --role analityk --no-semantic "ile procent zniżki ma klient ze Szwecji?"
"""
import argparse
import json
import sys

from security.company_policies import CompanyPolicyEngine


def _no_semantic(text, categories, policy):
    return {"category": "none", "confidence": 0.0, "reason": "klasyfikator wyłączony (--no-semantic)"}


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m security.company_policies")
    parser.add_argument("text", nargs="?", help="prompt, kontekst albo odpowiedź do sprawdzenia")
    parser.add_argument("--role", default="podstawowy użytkownik")
    parser.add_argument("--point", choices=["input", "retrieval", "output"], default="input")
    parser.add_argument("--destination", choices=["internal", "external_llm", "external_destination"])
    parser.add_argument("--model", help="model docelowy; spoza Allowed Models = zewnętrzny")
    parser.add_argument("--no-semantic", action="store_true", help="bez wywołania lokalnego modelu")
    parser.add_argument("--status", action="store_true", help="wersja polityki, liczba reguł, błędy")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")  # konsola Windows domyślnie psuje polskie znaki

    kwargs = {"classifier": _no_semantic} if args.no_semantic else {}
    engine = CompanyPolicyEngine(**kwargs)

    if args.status or not args.text:
        print(json.dumps(engine.status(), ensure_ascii=False, indent=2))
        return

    if args.point == "input":
        verdict = engine.check_input(args.role, args.text, args.destination, args.model)
    elif args.point == "retrieval":
        verdict = engine.filter_context(args.role, args.text, model=args.model)
    else:
        verdict = engine.check_output(args.role, args.text)

    print(f"{verdict.decision.upper()}: {verdict.reason}")
    print(json.dumps(verdict.details, ensure_ascii=False, indent=2, default=str))
    sys.exit(1 if verdict.is_blocked else 0)


if __name__ == "__main__":
    main()
