# Moduł „Dokumenty i regulaminy firmowe”

Moduł pilnuje, żeby ani pracownik, ani agent działający w jego imieniu nie łamał regulaminów
firmy i zobowiązań do poufności (NDA, oświadczenie o tajemnicy przedsiębiorstwa, polityka AI).

**Moduł nie tworzy własnych ról.** Działa na rolach z `config.ROLES` i dokłada do nich ograniczenia
wynikające z dokumentów firmowych. Agent nie ma osobnych uprawnień: każde sprawdzenie dostaje rolę
użytkownika, a treść promptu („jestem administratorem”) jej nie zmienia.

## Struktura

```
data/
├── company_documents/  # 4 fikcyjne dokumenty .md; paragrafy objęte kontrolą mają znacznik <!-- control: ID -->
└── company_fixtures/   # fikcyjne materiały .md z klauzulą POUFNE / ŚCIŚLE POUFNE (fingerprinting, testy)

security/company_policies/
├── rules.txt        # centralny plik reguł (format jak security/rules.txt), hot reload
├── docreader.py     # odczyt dokumentów .md; tu wpina się konwerter .docx/.pdf → .md (roadmapa)
├── policy.py        # parser, walidacja, spójność z dokumentami, PolicyStore (ostatnia poprawna wersja)
├── detection.py     # detekcja deterministyczna, fingerprinting, klasyfikator semantyczny
├── enforcer.py      # CompanyPolicyEngine: dostęp → użycie → detekcja → decyzja + audyt
├── gate.py          # PolicyToolGate: bramka dla agent.run_agent(tool_gate=...)
├── audit.py         # JSONL: hash zamiast treści, latencje warstw
└── __main__.py      # CLI do sprawdzania na żywo
```

Ścieżki do danych są w `config.py` (`COMPANY_DOCUMENTS_DIR`, `COMPANY_FIXTURES_DIR`). Oba foldery są
celowo poza `CONTEXT_FOLDERS`, więc agent nie odczyta ich narzędziami `read_file` / `list_files`.
`Source` w `rules.txt` wskazuje plik w `company_documents/`, a `Fingerprint` — plik w `company_fixtures/`.

## Przepływ

```
prompt ─► check_input ──────────► agent ─► wywołanie narzędzia ─► check_tool_call
                                              │
                                     wynik narzędzia ─► filter_context ─► model
                                                                            │
                                            odpowiedź modelu ─► check_output ─► użytkownik

każde sprawdzenie: rola (z konta) → DOSTĘP (Allowed Roles) → UŻYCIE (cel: internal /
external_llm / external_destination) → detekcja deterministyczna → semantyczna (tylko gdy
deterministyczna nic nie znalazła i wynik może zmienić decyzję) → block / redact / warn / log_only
```

- **Dostęp:** czy rola w ogóle może widzieć te informacje (`Allowed Roles`).
- **Użycie:** czy rola, która ma dostęp, może je wysłać do zewnętrznego modelu, na zewnętrzny adres
  albo użyć wewnętrznie (`External LLM`, `External Destinations`, `Summarize Internal`).
  Cel jest wykrywany z treści (słowa kluczowe, adresy e-mail i URL spoza `Internal Domains`),
  z nazwy narzędzia (`External Tools`) albo z modelu: model spoza `Allowed Models` jest zewnętrzny.
- **Kontekst** (wynik narzędzia, RAG) jest filtrowany *zanim* trafi do modelu.

## Detekcja

| Warstwa | Metoda | Pole w rules.txt |
|---|---|---|
| deterministyczna | słowa kluczowe (rdzenie, bez wielkości liter) | `Keywords` |
| deterministyczna | klauzule „POUFNE”, „ŚCIŚLE POUFNE” (wielkie litery) | `Markers` |
| deterministyczna | regex (numery umów, adresy, klucze) | `Regex` |
| deterministyczna | fingerprinting: hashe 8-wyrazowych n-gramów plików z `data/company_fixtures/` (bez tekstu wspólnego dla kilku plików, np. nagłówków szablonu) | `Fingerprint` |
| semantyczna | lokalny model (Ollama) zwraca `{category, confidence, reason}` | `Semantic Classifier`, `Semantic Threshold` |

Klasyfikator dostaje treść użytkownika jako dane między znacznikami, a nie jako polecenie.
Znaczniki są usuwane z treści, żeby nie dało się „zamknąć” bloku danych. Używa providera
z nagłówka (`Semantic Provider: ollama`), więc poufna treść nie trafia do zewnętrznego API.
Gdy klasyfikator nie działa, decyzję podejmuje `On Detector Error` (fail-closed dla `block`).

## Edycja na żywo (dla jury)

Polityka jest przeładowywana, gdy zmieni się `rules.txt` albo którykolwiek plik w `data/company_documents/`
lub `data/company_fixtures/`. Nie trzeba restartu. Zmiany są sprawdzane najwyżej raz na
`COMPANY_POLICIES_RELOAD_INTERVAL` sekund (domyślnie 1 s), więc między sprawdzeniami zapytania nie
dotykają dysku.

Oznaczenie paragrafu: linia `<!-- control: ID_REGUŁY -->` bezpośrednio nad numerowanym ustępem.
Reguła w `rules.txt` musi wskazywać ten sam ustęp w polu `Source`, inaczej zmiana nie zostanie przyjęta.

```
cd backend
python -m security.company_policies --status
python -m security.company_policies --no-semantic --role "podstawowy użytkownik" "Jakie rabaty mamy w cenniku?"
#   BLOCK: Zablokowano zgodnie z §3 ust. 2 Oświadczenia o poufności ...
```

Następnie w `rules.txt`, w regule `NDA-HY26-04`:

- `On Violation: redact` → ta sama komenda zwraca `REDACT` z zamaskowanymi słowami,
- `Enabled: false` → `PASS`,
- `Allowed Roles: *` → każda rola ma dostęp, ale wysyłka do ChatGPT dalej jest blokowana (użycie),
- literówka, np. `On Violation: explode` → zostaje poprzednia wersja, a `--status` pokazuje `last_error`.

Bez `--no-semantic` CLI woła lokalny model z nagłówka (`Semantic Model`).

## Pola reguły

| Pole | Znaczenie |
|---|---|
| `Rule` | identyfikator, taki sam jak znacznik `control:` w dokumencie |
| `Source` | `dokument.md \| §N ust. M`; przy ładowaniu sprawdzane, czy ten ustęp ma znacznik `control: ID` |
| `Authored By`, `Version` | pochodzenie i wersja reguły (patrz roadmapa) |
| `Category`, `Classification` | kategoria do raportów; public / internal / confidential / strictly_confidential |
| `Allowed Roles` | role z `config.ROLES` (aliasy jak w prompt_guard), `*` = wszystkie, `none` = nikt |
| `On Violation` | `block` / `redact` / `warn` / `log_only` |
| `On Detector Error` | `block` / `warn` / `log_only` |
| `Notify` | kogo powiadomić (trafia do audytu) |
| `Required Refusal` | komunikat dla użytkownika: wskazuje źródło i nie powtarza poufnej treści |

## Audyt i telemetria

Każda decyzja to jedna linia w `logs/audit.jsonl` (ścieżka: `COMPANY_POLICIES_AUDIT_LOG`):
czas, rola, punkt (input / retrieval / tool / output), reguła, dokument i paragraf, kategoria,
warstwa i metoda detekcji, confidence, decyzja, rodzaj naruszenia (access / usage), wersja polityki,
latencja każdej warstwy. **Zamiast treści zapisywany jest SHA-256 i długość.**
Przeładowania polityki (`policy_loaded`, `policy_reload_failed`) też trafiają do logu.

## Wydajność

- Polityka (reguły, skompilowane wzorce, odciski dokumentów, tytuły, katalog kategorii klasyfikatora)
  jest budowana raz przy załadowaniu; każdy dokument jest czytany raz na przeładowanie.
- Sprawdzenie zmian plików: najwyżej co `COMPANY_POLICIES_RELOAD_INTERVAL` s, przez `os.scandir`.
- Wyniki klasyfikatora semantycznego są zapamiętywane (ostatnie 512 tekstów, klucz: SHA-256 treści).
  Ten sam tekst nie trafia drugi raz do modelu; cache jest czyszczony po każdej zmianie polityki,
  a błędy klasyfikatora nie są zapamiętywane. W szczegółach decyzji widać to jako `semantic.cached`.
- Plik audytu jest otwierany raz, nie przy każdej decyzji.

Narzut warstwy deterministycznej to ok. 0,05 ms na krótki prompt i kilka ms na 50 KB wyniku
narzędzia. Dominującym kosztem pozostaje wywołanie lokalnego modelu, gdy jest potrzebne.

## Integracja z agentem

```python
from security.company_policies import PolicyToolGate, get_engine
from security.tool_whitelist import ToolGate

engine = get_engine()
verdict = engine.check_input(role, prompt)
if not verdict.is_blocked:
    gate = PolicyToolGate(engine, role, inner=ToolGate(role), model=config.MODEL)
    answer, history = agent.run_agent(prompt, history, tool_gate=gate)
    answer_verdict = engine.check_output(role, answer)
```

`PolicyToolGate` sam wykonuje narzędzie i zwraca agentowi przefiltrowany wynik, więc nie wymaga
zmian w `agent.py`.

## Testy

```
cd backend
python -m pytest tests/test_company_policies.py -v
```

Testy pokrywają 18 przypadków z instrukcji oraz dodatkowe przypadki brzegowe. Klasyfikator
semantyczny jest w nich podmieniony, więc nie potrzebują Ollamy. Pracują na kopii `rules.txt`
w katalogu tymczasowym.

Role z instrukcji przypisano do istniejących ról: employee → podstawowy użytkownik,
sales → bankier, finance → analityk, engineering → IT, security → administrator.
Kontraktor spoza zakresu NDA jest reprezentowany przez rolę prawnik.

## Dokumenty: prototyp a wersja docelowa

W firmach regulaminy, umowy i NDA są w formatach .docx i .pdf. Docelowy przepływ wygląda tak:

```
.docx / .pdf  ─►  konwerter do Markdown  ─►  data/company_documents/*.md  ─►  moduł (reguły, detekcja)
```

**W prototypie pomijamy etap konwersji** i od razu pracujemy na plikach .md. Fikcyjne dokumenty
są napisane bezpośrednio w Markdown. W oficjalnym projekcie byłby konwerter, np. oparty na
pandoc, `python-docx` / `pdfplumber` albo MarkItDown. Zachowywałby strukturę paragrafów (§, ustępy)
i przenosił oznaczenia kontroli, np. z komentarzy Worda, do znaczników `<!-- control: ID -->`.

Konwerter wpina się w jednym miejscu: `docreader.py` jest jedynym kodem, który czyta pliki dokumentów.
Pozostałe części modułu działają na tekście i nie zależą od formatu źródłowego. Plik w innym formacie
(np. `.pdf` wskazany w `Source`) jest dziś odrzucany przy walidacji z komunikatem o braku konwertera.

## Roadmapa: reguły wyciągane przez LLM

1. Compliance wgrywa nowy dokument (.docx/.pdf), a konwerter zamienia go na Markdown.
2. LLM proponuje reguły (`Authored By: llm_extracted`, `Enabled: false`) ze wskazaniem `Source`.
3. Osoba z compliance zatwierdza, poprawia albo odrzuca propozycję. Po zatwierdzeniu reguła dostaje
   `Enabled: true` i podbitą `Version`.

W prototypie wszystkie reguły są pisane ręcznie (`Authored By: manual`). Dzięki temu człowiek ma pełną
kontrolę i jednoznacznie odpowiada za ich treść.

## Zastrzeżenia

- Wszystkie dokumenty, firmy, kwoty, numery umów i adresy są **fikcyjne**.
- Narzędzie wspiera egzekwowanie polityk. Nie stanowi porady prawnej i nie zastępuje oceny prawnika
  ani compliance.
- Wdrożenie u realnego pracodawcy wymaga poinformowania pracowników o monitoringu (art. 22³ KP).
- Słowa kluczowe dają fałszywe alarmy, a klasyfikator semantyczny może przeoczyć treść. Reguły trzeba
  stroić na prawdziwych przykładach.
