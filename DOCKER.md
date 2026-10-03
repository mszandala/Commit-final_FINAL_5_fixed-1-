# Uruchamianie proxy Gemma 4 w kontenerach

Repozytorium uruchamia **dwa kontenery**: `proxy` (HTTP, OpenRouter, dane banku) i `executor` (obliczenia Python przez prywatny Unix socket). Model Gemma 4 działa w OpenRouter, nie w tych obrazach. `compose.yaml` korzysta z nazwanych wolumenów dla socketu i cache GLiNER; nie wymaga ustawiania UID ani montowania katalogu socketu z hosta. Tylko `backend/data/` jest montowany z repozytorium — wyłącznie w proxy i tylko do odczytu.

## Wymagania

- Linux: Docker Engine i plugin Docker Compose; alternatywnie rootless Podman z dostawcą Compose (instrukcja niżej).
- Windows: Docker Desktop w trybie **Linux containers** z WSL 2 oraz PowerShell. Uruchamiaj polecenia w katalogu repozytorium udostępnionym Docker Desktop.
- Git LFS: przed startem pobierz dane poleceniem `git lfs pull` (pliki giełdowe są duże).
- Własny klucz OpenRouter do wybranego modelu Gemma 4. `OPENROUTER_API_KEY` jest wyłącznie w proxy; token klienta `PROXY_API_KEYS` jest osobnym sekretem. Nie zapisuj ich w repozytorium ani nie wysyłaj w czacie.

Port HTTP jest dostępny tylko na `127.0.0.1:8080` hosta. Nie wystawiaj go publicznie bez reverse proxy z HTTPS i kontroli dostępu.

## Linux — Docker Compose

W nowym terminalu przejdź do katalogu repozytorium, wykonaj `git lfs pull`, a potem:

```bash
read -r -s -p 'Klucz OpenRouter: ' OPENROUTER_API_KEY; printf '\n'
export OPENROUTER_API_KEY
PROXY_TOKEN="$(openssl rand -hex 24)"
export PROXY_API_KEYS="{\"$PROXY_TOKEN\":\"bankier\"}"
printf 'Zapisz token klienta w menedżerze haseł: %s\n' "$PROXY_TOKEN"
docker compose up -d --build
```

**Nie generuj nowego tokenu przy każdym uruchomieniu.** W kolejnym terminalu wczytaj wcześniej zapisany `PROXY_TOKEN`, ustaw te same zmienne i ponownie użyj `docker compose up -d` tylko gdy zmieniasz konfigurację. Zmiana `PROXY_API_KEYS` oraz odtworzenie kontenera unieważnia poprzednie tokeny. Rola `bankier` nie ma dostępu do `run_python`; inne role definiuje `backend/config.py`. Nadawaj minimalne wymagane uprawnienia.

## Windows — Docker Desktop (PowerShell)

W PowerShell przejdź do katalogu repozytorium, wykonaj `git lfs pull`, a następnie:

```powershell
$secret = Read-Host 'Klucz OpenRouter' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try { $env:OPENROUTER_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
$bytes = New-Object byte[] 24
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$proxyToken = -join ($bytes | ForEach-Object { $_.ToString('x2') })
$mapping = @{}
$mapping[$proxyToken] = 'bankier'
$env:PROXY_API_KEYS = ConvertTo-Json $mapping -Compress
Write-Host "Zapisz token klienta w menedżerze haseł: $proxyToken"
docker compose up -d --build
```

Przy kolejnych uruchomieniach użyj **tego samego zapisanego tokenu** zamiast losować nowy; ustaw ponownie `OPENROUTER_API_KEY` i `PROXY_API_KEYS` w bieżącej sesji PowerShell. Nie wklejaj sekretów do plików projektu.

## Wywołanie API

Proxy obsługuje `POST /v1/chat/completions`, **jedną** wiadomość `user` i odpowiedź bez streamingu. Model i dostępne narzędzia wybiera proxy; klient nie przesyła własnych narzędzi, roli ani wiadomości `system`.

Linux (w terminalu, w którym ustawiono `PROXY_TOKEN`):

```bash
curl -i --connect-timeout 3 --max-time 120 http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $PROXY_TOKEN" -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"Cześć"}]}'
```

Windows PowerShell (w sesji, w której ustawiono `$proxyToken`):

```powershell
$body = @{ messages = @(@{ role = 'user'; content = 'Cześć' }) } | ConvertTo-Json -Depth 4 -Compress
$response = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/v1/chat/completions' -Method Post `
  -Headers @{ Authorization = "Bearer $proxyToken" } -ContentType 'application/json; charset=utf-8' `
  -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 120
$response.choices[0].message.content
```

Przy HTTP 200 tekst znajduje się w `choices[0].message.content`. `401` oznacza błędny/utracony **token klienta**, a nie klucz OpenRouter; `403` to odmowa polityki. `429` od OpenRouter oznacza limit dostawcy — nie rozwiązuj go automatycznie przez zmianę na płatny model. Proxy może obecnie zwrócić wtedy `502` (szczegóły typu błędu są w logu). Pierwsze wywołanie może potrwać dłużej, bo proxy ładuje model PII do wolumenu `pii-model-cache`.

Albo używacie postmana lub innego yaaka i wtedy bearer tocken i w do `http://127.0.0.1:8080/v1/chat/completions` wysyłacie json
```json
{"messages":[{"role":"user","content":"Cześć"}]}
```
## Stan i diagnostyka

```text
docker compose ps
docker compose logs --tail=80 proxy executor
docker compose down
```

W PowerShell i powłoce Linuksa powyższe polecenia są takie same. `down` zatrzymuje kontenery; **nie** usuwa danych w nazwanych wolumenach. Nie stosuj `down --volumes`, jeśli chcesz zachować cache modelu. Nie przekazuj osobom trzecim logów ani tokenów bez sprawdzenia ich zawartości. Po zmianie zależności proxy przebuduj obraz przez `docker compose up -d --build proxy` (lub `podman compose up -d --build proxy` przy Podmanie); samo ponowienie żądania używa starego obrazu.

Po ponownym zbudowaniu proxy udane użycie narzędzia jest widoczne jako `tool allowed role=administrator tool='run_python'` w logach proxy. Sam ten wpis nie dowodzi jeszcze wykonania kodu: sprawdź także wynik obliczenia; odrzucony kod może zakończyć się przed połączeniem z executorem.

## Linux — rootless Podman zamiast Docker Engine

`podman compose` może korzystać z zewnętrznego `/usr/bin/docker-compose`. Jeżeli zgłasza brak serwera API, uruchom socket Podmana i ustaw `DOCKER_HOST`:

```bash
systemctl --user start podman.socket
export DOCKER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
podman compose up -d --build
```

Pozostałe zmienne `OPENROUTER_API_KEY` i `PROXY_API_KEYS` ustaw tak jak w sekcji Linux. Sprawdzaj stan przez `podman compose ps`, a logi przez `podman compose logs --tail=80 proxy executor`. Nie używaj tu starej instrukcji `podman unshare chown` dla katalogu hosta: socket i cache są teraz **nazwanymi wolumenami**. Jeżeli wolumen z poprzedniej konfiguracji ma zły UID/mode, nie usuwaj go w ciemno; sprawdź uprawnienia i zachowaj jego dane.

Executor jest odłączony od sieci, działa bez roota i bez montowania danych bankowych; samo uruchomienie kontenera nie stanowi gwarancji izolacji dowolnie złośliwego kodu. Dla silniejszego modelu zagrożeń potrzebny jest sandbox taki jak gVisor/microVM. Uruchomienie na Windows wymaga weryfikacji na Docker Desktop — nie zostało przetestowane na tym stanowisku.
