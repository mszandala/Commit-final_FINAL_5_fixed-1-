# API v1 — warstwa bezpieczeństwa

Wersja robocza do uzgodnienia z frontendem. Źródłem prawdy jest schemat OpenAPI serwera.

## Uruchomienie

```
cd backend
python main.py
```

- adres bazowy: `http://127.0.0.1:8000/api/v1`
- dokumentacja interaktywna: `http://127.0.0.1:8000/docs`, schemat: `/openapi.json`
- CORS wpuszcza `http://localhost:5173` (Vite); inne adresy przez `CORS_ORIGINS` w `.env`
- pola JSON są w camelCase
- brak logowania: rolę wybiera klient polem `roleId` (wersja demonstracyjna)
- stan (rozmowy, log, budżety, zmiany konfiguracji) żyje w pamięci serwera do restartu

## Endpointy

| Metoda | Ścieżka | Do czego | Zastępuje w mockach |
|---|---|---|---|
| GET | `/meta` | słowniki: modele, poziomy czułości, obszary dostępu, typy PII, nazwy etapów, przykłady | stałe z `mock/config.js`, `getExamples()` |
| GET | `/roles` | role do wyboru w czacie z użytkownikiem i stanem budżetu | `USERS` z `mock/data.js` |
| GET | `/config` | bieżąca konfiguracja | `getConfig()` |
| GET | `/config/defaults` | konfiguracja startowa, bez stosowania (do wypełnienia formularza) | „Reset to defaults" |
| PUT | `/config` | zmiana konfiguracji (pola opcjonalne) | zapis formularza |
| POST | `/config/reset` | powrót do wartości startowych | „Reset to defaults" |
| POST | `/chat` | jedna wiadomość, odpowiedź po całej turze | `sendMessage()` |
| POST | `/chat/stream` | to samo jako strumień SSE z etapami | `sendMessage(…, onProgress)` |
| DELETE | `/conversations/{id}` | koniec rozmowy | zmiana użytkownika |
| GET | `/events` | wiersze logu; `afterId` dociąga tylko nowe | `getEvents()`, `subscribeEvents()` |
| GET | `/events/{id}` | szczegóły tury: zamaskowany prompt, narzędzia, ślad audytu | — |
| GET | `/stats` | podsumowanie logu dla zakładki Dashboard | — |
| GET | `/health` | czy serwer żyje, jaki model | — |

## Czat

Żądanie (`POST /chat` i `POST /chat/stream`):

```json
{ "roleId": "banker", "message": "Podaj dane klienta o customer_id 15647311", "conversationId": null }
```

`conversationId` puste zaczyna nową rozmowę; odpowiedź zwraca id do kolejnych wiadomości.
Zmiana roli = nowa rozmowa (id innej roli daje 409).

Odpowiedź (`ChatResponse`):

```json
{
  "conversationId": "19a10438b5b3",
  "eventId": 1,
  "text": "Dane klienta o customer_id 15647311: ...",
  "tools": [
    { "tool": "read_client_records",
      "args": { "column": "customer_id", "value": "ID-b1813ca0cf", "limit": 1 },
      "allowed": true, "stage": null, "reason": null }
  ],
  "verdict": null,
  "verdicts": [],
  "maskedForModel": ["CLIENT-ID"],
  "tokens": 4323,
  "cost": 0.00048,
  "latencyMs": 20086,
  "budget": { "limit": 50000, "used": 4323, "spendingLimit": 0.5, "spent": 0.00048 }
}
```

- `text` jest `null`, gdy tura została zablokowana; powód jest wtedy w `verdict`.
- `verdict` to najważniejsza decyzja tury albo `null`:
  `{ "decision": "warn" | "refuse" | "redact" | "block", "stage": "...", "reason": "..." }`.
- `refuse` (etap `chatbot_refusal`) oznacza, że warstwa niczego nie zablokowała, ale sam chatbot odmówił:
  `text` zawiera wtedy jego odpowiedź. Odmowę rozpoznają lokalnie słowa kluczowe i model embeddingów.
- `stage` to klucz z `GET /meta → controls`: `prompt_guard`, `tool_whitelist`, `pii_policy`,
  `code_guard`, `company_policies`, `budget`. Lista może rosnąć (np. o sędziów LLM), więc nazwę do wyświetlenia
  warto brać z `/meta`, a nieznany klucz pokazywać wprost.
- `verdicts` to wszystkie decyzje tury, od najważniejszej; `verdict` to jej pierwszy element. Przykład:
  ostrzeżenie strażnika promptu i ukrycie e-maila w tej samej turze dają `["redact", "warn"]`.
- `maskedForModel` to typy danych z promptu, które chatbot dostał jako znaczniki. Wartości wpisane
  przez użytkownika wracają do niego w odpowiedzi, więc bez tego pola maskowanie nie byłoby widać.
- Odrzucone wywołanie narzędzia ma `allowed: false` oraz `stage` i `reason`.
- Argumenty narzędzi są w postaci zamaskowanej (np. `ID-b1813ca0cf` zamiast numeru klienta).
- Ukryte dane w `text` mają postać `[TYP]`, np. `[EMAIL]`, `[PHONE-NO]`, `[SALARY]`; komórki
  tabel ukryte u źródła mają `[REDACTED]`. Nazwy dla ludzi: `GET /meta → piiLabels`. Fragmenty
  ukryte przez regulaminy firmowe mają postać `[ZASTRZEŻONE: ID-REGUŁY]`.
- `reason` jest po polsku.

### Strumień (`POST /chat/stream`)

Odpowiedź `text/event-stream`. Ponieważ to POST, w przeglądarce trzeba czytać go przez `fetch`
i `response.body.getReader()`, a nie przez `EventSource`.

| Zdarzenie | Dane | Kiedy |
|---|---|---|
| `stage` | `{ "stage": "checking_request" \| "waiting_for_model" \| "checking_reply" }` | zmiana etapu |
| `tool` | obiekt jak w `tools` (także wywołania subagenta) | po każdym wywołaniu narzędzia |
| `result` | pełny `ChatResponse` | koniec udanej tury |
| `error` | `{ "status": 502, "detail": "..." }` | błąd; strumień się kończy |

Nazwy etapów dla ludzi są w `GET /meta → stages`. Nieznana rola lub rozmowa daje zwykłe 404/409
przed otwarciem strumienia; zdarzenie `error` dotyczy tylko błędów w trakcie tury.

### Błędy

| Kod | Kiedy |
|---|---|
| 404 | nieznana rola, rozmowa albo zdarzenie |
| 409 | `conversationId` należy do innej roli |
| 422 | błędne dane (pusta wiadomość, nieznana wartość w konfiguracji) |
| 502 | model nie odpowiedział; nadaje się do przycisku „Retry". Tura trafia do logu jako `Error`, a zużyte tokeny do budżetu |

Wyczerpany budżet tokenów nie jest błędem: zwraca 200 z `text: null` i werdyktem `budget`.

## Konfiguracja

`GET /config`:

```json
{
  "provider": "openrouter",
  "model": "google/gemma-4-26b-a4b-it",
  "apiKeySet": true,
  "apiKeyHint": "30a5",
  "sensitivity": "balanced",
  "piiThreshold": 0.35,
  "guardMode": "warn",
  "maskPii": true,
  "roles": [
    { "id": "hr", "label": "HR", "access": ["projects", "hr"], "pii": ["SALARY", "ORGANIZATION", "PROJECT"] }
  ]
}
```

`PUT /config` przyjmuje te same pola (bez `apiKeySet`, `apiKeyHint`, `piiThreshold`) plus `apiKey`;
każde pole jest opcjonalne, pominięte zostaje bez zmian. Zwraca nową konfigurację.

Różnice względem `mock/config.js`:

- **Klucz API nie wraca z serwera.** Jest tylko `apiKeySet` i cztery ostatnie znaki w `apiKeyHint`.
  Pole z podglądem klucza może pokazywać wyłącznie to, co użytkownik właśnie wpisał.
- **`sensitivity` to id poziomu** (`low` / `balanced` / `high`), nie indeks. `null` oznacza próg
  spoza listy.
- **`guardMode`:** `warn` przepuszcza i oznacza, `block` zatrzymuje zapytanie przed modelem.
- **`maskPii: false`:** dane nie są ukrywane w odpowiedzi ani maskowane przed modelem; typy zawsze
  blokujące (hasło, numer karty) nadal blokują.
- **`roles[].access`** mapuje się na narzędzia z `GET /meta → dataAccess`. Analityk ma także
  `clients` (rekordy klientów z pseudonimami zamiast identyfikatorów).
- **`roles[].pii`** dotyczy tylko typów z `GET /meta → piiTags`; `redactedPii` i `blockedPii`
  obowiązują każdą rolę i nie są edytowalne.

## Role

`GET /roles` zwraca dla każdej roli to, co `roles[]` w konfiguracji, oraz:

```json
{ "description": "Dział kadr; ...", "user": "Anna Wiśniewska",
  "budget": { "limit": 50000, "used": 0, "spendingLimit": 0.5, "spent": 0.0 } }
```

Rola ma dwa limity i blokuje ten, który wyczerpie się pierwszy (werdykt `budget`):

- `limit` / `used` — dzienny budżet tokenów, liczony z faktycznego zużycia zgłaszanego przez dostawcę
  modelu,
- `spendingLimit` / `spent` — łączny limit wydatków w dolarach (`MAX_SPENDING`), bez dziennego zerowania.

Do obu limitów liczą się tylko wywołania chatbota. Strażnicy i sędziowie (strefa bezpieczeństwa)
docelowo działają lokalnie, więc ich zużycie nie obciąża użytkownika; jest widoczne w śladzie audytu
tury (`securityTokens`, `securityCost` w zdarzeniu `turn`).

Zużycie jest zapisywane w `backend/spending.db`, więc przetrwa restart serwera. Aktualny stan wraca
też w każdej odpowiedzi czatu.

## Log

`GET /events?limit=200&decision=Blocked` — ostatnie `limit` wierszy, od najstarszego;
z `afterId` — kolejne wiersze po nim:

```json
{
  "id": 2,
  "time": "2026-10-03T19:42:11.120Z",
  "user": "Piotr Nowak",
  "role": "Employee",
  "roleId": "basic_user",
  "conversationId": "f477c1b68c16",
  "decision": "Blocked",
  "stage": "tool_whitelist",
  "control": "Tool permissions",
  "reason": "read_employee_records: Narzędzie niedostępne dla roli „podstawowy użytkownik”",
  "maskedForModel": [],
  "model": "google/gemma-4-26b-a4b-it:free",
  "tokens": 3655,
  "latencyMs": 4152
}
```

- Jedna tura to jeden wiersz. `decision`: `Allowed`, `Redacted`, `Blocked` albo `Error` (model nie
  odpowiedział). Ostrzeżenie strażnika promptu przy innej decyzji jest dopisane do `reason`.
- Tura z odrzuconym narzędziem jest `Blocked`, nawet jeśli użytkownik dostał odpowiedź
  (tak jak w mockach).
- Odświeżanie: odpytywanie `GET /events?afterId=<ostatnie id>` co kilka sekund; `eventId`
  z odpowiedzi czatu pozwala dociągnąć wiersz od razu.

`GET /events/{id}` dodaje `maskedPrompt` (prompt w postaci wysłanej do chatbota), `tools`,
`leaksToChatbot` (ile zamaskowanych wartości trafiło do chatbota; oczekiwane 0) oraz `trail` —
zdarzenia audytu tury z polem `zone` (`security`, `chatbot`, `local`), bez surowych wartości.

### Kroki tury

Każda tura ma `level` (`info`, `warn`, `block` — najwyższy poziom spośród jej kroków) i `stepCount`.
Kroki zwraca `GET /events/{id}` oraz `GET /events?steps=true`; `minLevel=warn` zostawia tury
z ostrzeżeniem lub blokadą, `minLevel=block` same blokady.

```json
{
  "index": 4,
  "kind": "tool_call",
  "label": "Tool call",
  "zone": "security",
  "level": "block",
  "summary": "read_employee_records(limit=1) rejected by Tool permissions: ...",
  "atMs": 1840,
  "durationMs": 2,
  "details": { "tool": "read_employee_records", "allowed": false, "stage": "tool_whitelist" }
}
```

- `kind`: `prompt_guard`, `company_policy`, `prompt_masking`, `pii_judge`, `model_call`, `tool_call`,
  `output_filter`, `refusal`, `budget`, `error`; nazwy w `GET /meta → stepKinds`.
- `zone`: `security`, `chatbot`, `local`; nazwy w `GET /meta → zones`.
- `level`: `info` — bez zastrzeżeń, `warn` — flaga, ostrzeżenie albo ukrycie danych, `block` — blokada,
  odrzucone narzędzie albo błąd.
- `summary` jest po angielsku; powody decyzji strażników zostają w oryginale.
- `atMs` to czas od początku tury, `durationMs` — czas od poprzedniego kroku.
- `details` to pełne zdarzenie audytu, bez surowych wartości wrażliwych.

Log jest zapisywany w `backend/audit/turns.jsonl` i wczytywany przy starcie serwera.

`GET /stats`:

```json
{ "total": 2, "byDecision": { "Allowed": 1, "Blocked": 1 }, "byControl": { "Tool permissions": 1 },
  "tokens": 7978, "avgLatencyMs": 12119 }
```

## Czego w v1 nie ma

- **Załączniki.** Composer pozwala dodać pliki, ale backend nie ma jeszcze ich obsługi.
- **Trwałość konfiguracji i rozmów.** Znikają po restarcie serwera; zostają log (`audit/turns.jsonl`,
  `audit/events.jsonl`) i budżety (`spending.db`).
- **Uwierzytelnianie.** Każdy klient może wybrać dowolną rolę i zmienić konfigurację.
