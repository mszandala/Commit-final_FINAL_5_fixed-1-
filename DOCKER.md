# Uruchamianie w Dockerze

Compose uruchamia trzy usługi: **backend** (API aplikacji demo, panel, metryki i proxy zgodne z OpenAI, jeden proces),
**frontend** (nginx z interfejsem, który przekazuje `/api` i `/v1` do backendu) oraz **executor** (osobny kontener,
który wykonuje kod z narzędzia `run_python`). Model językowy działa u dostawcy
(domyślnie OpenRouter); modele wykrywania danych osobowych i odmów są wbudowane w obraz, więc kontener nie potrzebuje
internetu do niczego poza wywołaniami modelu językowego.

## Wymagania

- Docker Desktop w trybie **Linux containers** (Windows: WSL 2) albo Docker Engine z wtyczką Compose.
- `git lfs pull`: pliki giełdowe w `backend/data/stock_market` są w Git LFS (bez tego narzędzia giełdowe nie mają danych).
- Klucz dostawcy modelu w `backend/.env` (wzór: `backend/.env.example`), np. `OPENROUTER_API_KEY=...`. Compose wczytuje
  go przy starcie; do obrazu nie trafia (`.dockerignore` wyklucza `.env`).

## Start

```bash
docker compose up -d --build
```

| Adres | Co |
|---|---|
| http://127.0.0.1:8080 | interfejs (czat, panel, konfiguracja) |
| http://127.0.0.1:8000/docs | dokumentacja API (OpenAPI) |
| http://127.0.0.1:8000/v1 | proxy zgodne z OpenAI (`base_url` dla aplikacji) |

Porty są otwarte tylko na `127.0.0.1`. Publiczny dostęp wymaga reverse proxy z HTTPS i kontroli dostępu.
Gdy porty 8000 lub 8080 są zajęte: `API_PORT=18000 UI_PORT=18080 docker compose up -d --build` (zmienne można też
wpisać do pliku `.env` obok `compose.yaml`).

```bash
docker compose ps                  # stan i zdrowie usług
docker compose logs -f backend     # logi
docker compose down                # zatrzymanie (wolumen `state` zostaje)
docker compose down -v             # zatrzymanie i usunięcie stanu (log audytu, bazy, nadpisania z panelu)
```

## Proxy dla innych aplikacji

Aplikacja zmienia tylko `base_url` i klucz API; rolę wyznacza klucz (sekcja `clients` w `policy/policy.yaml`).
Klucze demo (jawne, tylko do demonstracji): `sk-demo-basic-user`, `sk-demo-hr`, `sk-demo-banker`, `sk-demo-admin`.
Własny klucz: `python -m proxy new-key nazwa "rola"` wypisuje klucz i wpis do polityki (w pliku jest tylko skrót).

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="sk-demo-hr")
reply = client.chat.completions.create(
    model="google/gemma-4-26b-a4b-it",
    messages=[{"role": "user", "content": "Cześć, w czym możesz mi pomóc?"}],
)
print(reply.choices[0].message.content)
print(reply.model_extra["x_security"]["decision"])      # pass | redact | refuse | block
```

Odpowiedź ma dodatkowe pole `x_security` (decyzja, ślad kontroli, wersja polityki) i nagłówki `X-Session-Id`,
`X-Security-Decision`, `X-Policy-Version`. Kolejne żądania tej samej rozmowy łączy nagłówek `X-Session-Id`.
Streaming (`stream: true`) nie jest jeszcze obsługiwany.

## Polityka na żywo

`policy/policy.yaml` jest jedynym źródłem konfiguracji i jest montowany do kontenera **tylko do odczytu**.
Edytuj go na hoście: zmiana obowiązuje od następnego żądania, bez restartu. Błędny plik nie zatrzymuje serwera
(obowiązuje ostatnia poprawna wersja); stan i ewentualny błąd pokazuje `GET /api/v1/policy`. Zmiany z panelu
(przełączniki) trafiają do `/state/policy.overrides.json` w wolumenie i wygrywają z plikiem do czasu resetu.

## Testy dla jury

```bash
docker compose run --rm tests
```

Uruchamia cały zestaw (testy dozwolone i blokowane, budżety, ataki, proxy) w kontenerze, bez klucza i bez sieci:
model jest atrapą.

## Stan, logi i raporty

- Wolumen `state`: log audytu, baza rozmów i wydatków, nadpisania polityki.
- `AUDIT_SINK=stdout` w `backend/.env` wypisuje zdarzenia audytu jako JSON w liniach (`docker compose logs backend`).
- Eksport i metryki: `GET /api/v1/audit/export` (JSONL albo CSV), `GET /api/v1/metrics`.

## Wykonywanie kodu (executor)

Narzędzie `run_python` nie wykonuje kodu w backendzie. Backend sprawdza kod statycznie (`code_guard`), a potem wysyła
go przez gniazdo Unix do kontenera `executor`, który: nie ma sieci (`network_mode: none`), nie widzi danych ani
sekretów, ma system plików tylko do odczytu, limity procesów (32), pamięci (512 MB) i procesora (1), a każdy kod
ponownie sprawdza i wykonuje w osobnym procesie z limitem czasu (3 s), czasu procesora, pamięci (256 MB) i wyjścia
(8 KB). Nieskończona pętla kończy się zabiciem procesu, a nie zawieszeniem serwera. Bez zmiennej
`PYTHON_EXECUTOR_SOCKET` (uruchomienie lokalne bez Dockera) `run_python` działa jak dotąd, w procesie backendu.

## Utwardzenie

Kontenery działają bez roota (uid 10001 w backendzie), z systemem plików tylko do odczytu, `cap_drop: ALL`,
`no-new-privileges`, limitami procesów i pamięci. Zapisywalne są tylko `/state` i `/tmp`. Dane narzędzi są montowane
tylko do odczytu.

## Ograniczenia

- Executor to izolacja procesowa i kontenerowa, a nie gwarancja przy dowolnie złośliwym kodzie: dla silniejszego
  modelu zagrożeń potrzebny jest sandbox taki jak gVisor albo mikro-VM. Obsługuje jedno żądanie naraz.
- Bez Dockera (uruchomienie lokalne) `run_python` wykonuje kod w procesie backendu, po kontroli statycznej.
- Na hoście z Linuksem polityka i dane muszą być czytelne dla użytkownika o uid 10001.
- Pierwsze żądanie po starcie jest wolniejsze (ładowanie modeli do pamięci).
