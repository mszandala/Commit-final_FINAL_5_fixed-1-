"""Testy na żywym modelu z terminala (z katalogu backend/):

    python -m live_tests                 wszystkie scenariusze
    python -m live_tests attacks config  wybrane grupy albo id scenariuszy

Kod wyjścia 1, gdy któryś scenariusz nie przeszedł. Te same scenariusze uruchamia zakładka Tests w interfejsie.
"""
import sys

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

from live_tests.runner import load_catalog, run_scenario

MARKS = {"passed": "PASS", "failed": "FAIL", "error": "ERR "}


def main(args: list[str]) -> int:
    scenarios = load_catalog()["scenarios"]
    if args:
        scenarios = [s for s in scenarios if s["id"] in args or s["group"] in args]
    if not scenarios:
        print("Brak scenariuszy dla:", " ".join(args))
        return 2

    results = []
    for s in scenarios:
        r = run_scenario(s)
        results.append(r)
        print(f"{MARKS[r['status']]}  {s['id']:<32} {r.get('outcome', '-'):<9} {r['latencyMs']:>6} ms  {s['title']}")
        for c in r["checks"]:
            if not c["ok"]:
                print(f"      x {c['name']}: {c['detail']}")
        if r.get("error"):
            print(f"      x {r['error']}")

    passed = sum(r["status"] == "passed" for r in results)
    cost = sum(r.get("cost", 0) for r in results)
    print(f"\n{passed}/{len(results)} passed, cost ${cost:.4f}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
