# Architektura backendu — warstwa bezpieczeństwa dla chatbota AI

> Wersja robocza. Podział `data/` i `tools/` na domeny oraz przypisanie ról do narzędzi
> to propozycja — do korekty, gdy będzie wiadomo, jakie dane faktycznie mamy.

Stos: Python, Ollama, transformers (na podstawie istniejących `chat.py` i `PII_detector.py`).

## Struktura folderów i plików

```
backend/
├── main.py                     # start serwera API
├── config.py                   # role, whitelisty narzędzi, modele, limity
├── pipeline.py                 # orkiestracja całego flow, krok po kroku
├── api.py                      # endpointy dla interfejsu: /roles, /chat, /logs
│
├── chatbot/
│   ├── agent.py                # pętla czatu z narzędziami (z obecnego chat.py)
│   └── llm_client.py           # jedno miejsce wywołań Ollamy, wspólne dla agenta i strażników
│
├── security/
│   ├── prompt_guard.py         # 1. LLM: czy prompt zgodny z rolą → pass/block
│   ├── tool_whitelist.py       # 2a. deterministyczne sprawdzenie: narzędzie w whiteliście roli?
│   ├── tool_violation_judge.py # 2b. LLM: błąd modelu czy intencja użytkownika → retry/block
│   ├── regex_detector.py       # 3a. szybka detekcja regułowa (<0.1ms): hasła, e-maile, telefony
│   ├── gliner_detector.py      # 3b. semantyczna detekcja zero-shot NER: organizacje, kwoty, projekty
│   ├── pii_detector.py         # 3c. fasada łącząca reguły i model + deduplikacja
│   ├── pii_access_judge.py     # 3d. LLM: czy rola może zobaczyć wykryte dane → pass/block
│   ├── verdicts.py             # wspólne typy wyników: Verdict(decision, reason, stage)
│   └── prompts/
│       ├── prompt_guard.txt
│       ├── tool_violation_judge.txt
│       └── pii_access_judge.txt
│
├── tools/
│   ├── registry.py             # lista wszystkich narzędzi + mapa nazwa → funkcja
│   ├── _files.py               # wspólne: bezpieczna ścieżka, czytanie csv/txt
│   ├── public_tools.py         # regulaminy, FAQ
│   ├── hr_tools.py             # pracownicy, wynagrodzenia, urlopy
│   ├── banking_tools.py        # klienci, rachunki, transakcje
│   ├── it_tools.py             # inwentarz systemów, logi dostępu
│   ├── analytics_tools.py      # raporty, dane zagregowane
│   ├── legal_tools.py          # umowy, opinie prawne
│   └── portfolio_tools.py      # portfele, pozycje, notowania
│
├── data/
│   ├── public/                 # faq.txt, regulamin.txt
│   ├── hr/                     # employees.csv, salaries.csv, leave_policy.txt
│   ├── banking/                # customers.csv, accounts.csv, transactions.csv
│   ├── it/                     # systems.csv, access_logs.csv, security_policy.txt
│   ├── analytics/              # kpi_reports.csv, market_summary.txt
│   ├── legal/                  # contracts.csv, nda_template.txt, opinions.txt
│   └── portfolio/              # portfolios.csv, positions.csv, prices.csv
│
├── audit/
│   ├── logger.py               # zapis zdarzenia z każdego etapu pipeline'u
│   └── events.jsonl            # log, który czyta interfejs
│
└── tests/
    ├── test_agent.py
    ├── test_prompt_guard.py
    ├── test_tool_whitelist.py
    ├── test_pii.py
    └── attack_prompts.csv      # zestaw promptów testowych: rola, prompt, oczekiwany wynik
```

## `config.py`

Każda rola ma trzy pola, z których korzystają kolejne zabezpieczenia:

| Pole | Kto z niego korzysta |
|---|---|
| `description` (czym rola się zajmuje) | `prompt_guard`, oba sędziowie LLM |
| `allowed_tools` (whitelist) | `tool_whitelist` |
| `allowed_pii` (np. `["NAME", "SALARY"]`) | `pii_access_judge` |

Proponowane przypisanie narzędzi do ról:

| Rola | Narzędzia |
|---|---|
| podstawowy użytkownik | public |
| kadry | public, hr |
| bankier | public, banking |
| IT | public, it |
| analityk | public, analytics |
| prawnik | public, legal |
| Portfolio Manager | public, portfolio |
| administrator | wszystkie |

## Flow w `pipeline.py`

1. Użytkownik wybiera rolę.
2. `prompt_guard` ocenia prompt względem roli (pass/block); przy blokadzie pipeline kończy się od razu.
3. `agent` generuje odpowiedź, widząc **wszystkie** narzędzia z `registry` (celowo — testujemy zabezpieczenia, a nie ukrywanie narzędzi).
4. Każde wywołanie narzędzia przechodzi przez `tool_whitelist`. Jeśli narzędzie jest spoza listy, `tool_violation_judge` decyduje:
   - błąd modelu → agent dostaje polecenie pracy dalej bez tego narzędzia,
   - intencja użytkownika → odpowiedź jest blokowana.
5. `pii_detector` skanuje gotową odpowiedź; jeśli coś znajdzie, `pii_access_judge` decyduje, czy rola może to zobaczyć. Jeśli nie, odpowiedź się nie wyświetla.
6. Każdy etap zapisuje zdarzenie przez `audit/logger.py` — interfejs pokazuje je jako logi.

## Zmiany względem obecnego kodu

- **Whitelist przed wykonaniem narzędzia:** sprawdzenie musi nastąpić, zanim narzędzie się wykona. Inaczej dane spoza roli trafią do kontekstu modelu i mogą wyciec w kolejnej odpowiedzi.
- **`PII_detector.py` zwraca dziś tylko `bool`:** sędzia potrzebuje listy wykrytych encji (typ i fragment tekstu), więc funkcję trzeba rozszerzyć. Kod testowy z końca pliku przechodzi do `tests/`.
- **`write_file` wypada:** narzędzia mają tylko czytać, więc z `chat.py` przechodzą `read_file`, `list_files` i `_safe_path` (do `tools/_files.py`).

## Stan implementacji

Gotowe: `config.py`, `tools/_files.py`, `tools/registry.py`, `chatbot/llm_client.py`,
`chatbot/agent.py`, `security/pii/pii_detector.py`, `tests/test_agent.py`, `tests/test_pii.py`.

- Testy: `python -m pytest tests` uruchamiane z katalogu `backend/`.
- `agent.run_agent(message, history, tool_gate)` — `tool_gate` to miejsce na `tool_whitelist`
  i `tool_violation_judge`: zwraca `None` (wolno), tekst odmowy (model pracuje dalej bez narzędzia)
  albo rzuca `ResponseBlocked` (blokada odpowiedzi).
- `detect_pii(text)` zwraca listę encji `{type, text, start, end}` i skanuje cały tekst fragmentami.
- Whitelisty w `config.py` są tymczasowe: każda rola ma oba narzędzia ogólne.

## Do ustalenia

- Model PII: wdrożono hybrydowy model `urchade/gliner_small-v2.1` z regułami regex dla haseł,
  e-maili i numerów telefonów. Wykrywa encje: `NAME`, `ORGANIZATION`, `LOCATION`, `SALARY`, `PASSWORD`,
  `PROJECT`, `PHONE-NO`, `EMAIL`, `CREDIT-CARD-NO`. Skanuje długie teksty z podziałem na okna (sliding-window).

- Faktyczne dane: jakie pliki csv/txt, w jakich podfolderach `data/`.
- Wynikający z tego podział `tools/` i ostateczne whitelisty ról.
- Kategorie PII dozwolone dla każdej roli (`allowed_pii`).
