# security/: wszystko, co sprawdza lub blokuje

```
security/
├── common/                 # wspólne klocki, bez własnych decyzji
│   ├── verdicts.py         # Verdict: wynik każdego strażnika (pass / warn / redact / block)
│   ├── roles.py            # normalize_role, ROLE_ALIASES: alias roli → nazwa z config.ROLES
│   └── spans.py            # replace_spans (maskowanie fragmentów), by_position (kolejność encji)
│
├── prompt_guard.py         # prompt: wzorce injection/jailbreak + czy rola ma dostęp do zasobu
├── tool_whitelist.py       # ToolGate: narzędzie z allowed_tools roli?
├── code_guard.py           # analiza kodu przed run_python
│
├── pii/                    # dane osobowe w odpowiedzi
│   ├── regex_detector.py   # hasła, e-maile, telefony (EMAIL_PATTERN używa też company_policies)
│   ├── gliner_detector.py  # model GLiNER (ładowany dopiero przy pierwszym użyciu)
│   ├── pii_detector.py     # detect_pii: regex + GLiNER, bez nakładających się encji
│   └── pii_policy.py       # check_pii: co rola może zobaczyć, co maskować
│
├── company_policies/       # reguły z dokumentów firmy (regulaminy, NDA); opis w jej README.md
│
├── rules.txt               # ogólne reguły AI (decyzje kadrowe, dyskryminacja itp.)
└── prompts/                # prompty strażników opartych na LLM
```

Dane modułu `company_policies` są w `data/company_documents/` i `data/company_fixtures/`
(ścieżki w `config.py`).

## Zasada importów

- `common/` nie importuje niczego z `security/` (tylko `config`).
- Pozostałe części mogą importować z `common/`, a `company_policies` także z `pii/`.
- `prompt_guard`, `tool_whitelist`, `code_guard` i `pii/` nie importują `company_policies`.

Dzięki temu importy nie tworzą cyklu, a nowa funkcja pomocnicza używana w dwóch miejscach trafia do `common/`.

## Uruchamianie (z katalogu backend/)

```
python -m security.company_policies --status
python -m pytest tests -v
```
