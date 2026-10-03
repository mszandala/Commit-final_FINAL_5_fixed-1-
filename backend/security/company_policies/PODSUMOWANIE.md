# Moduł „Dokumenty i regulaminy firmowe”: podsumowanie

## Problem

Pracownik może poprosić asystenta AI o informacje, których zgodnie z regulaminem nie powinien
dostać, np. cennik z rabatami albo cudze wynagrodzenie. Może też wkleić poufny dokument do
zewnętrznego czatu. Agent AI działający w imieniu pracownika może zrobić to samo, nawet gdy
pracownik o to wprost nie prosi. Moduł pilnuje, żeby żadna z tych sytuacji nie łamała firmowych
regulaminów i zobowiązań do poufności.

## Skąd moduł bierze zasady

Fikcyjna firma **HackYeah2026 sp. z o.o.** ma cztery dokumenty w katalogu `data/company_documents/`:

| Dokument | Czego dotyczy |
|---|---|
| `regulamin_pracy.md` | klasy informacji, dane kadrowe, monitoring asystenta AI |
| `oswiadczenie_o_poufnosci.md` | tajemnica przedsiębiorstwa: klienci, cenniki, kod, projekty, zabezpieczenia |
| `nda_kontrahent.md` | NDA z fikcyjnym kontrahentem Nordic Freight AB |
| `polityka_ai.md` | zakaz wysyłania poufnych danych do zewnętrznych modeli, zakaz podszywania się |

Paragrafy, których przestrzeganie ma egzekwować moduł, mają nad sobą znacznik `<!-- control: ID -->`
(np. `<!-- control: NDA-HY26-04 -->`). Każdy taki paragraf ma regułę w pliku `rules.txt`, napisaną ręcznie
przez zespół w tym samym formacie co `security/rules.txt`.

**Prototyp a wersja docelowa.** Firmy trzymają takie dokumenty w formatach .docx i .pdf. W docelowym
systemie konwerter zamieniałby je na Markdown, a moduł pracowałby na wyniku konwersji. W prototypie
pomijamy ten etap: dokumenty są od razu w Markdown. Szczegóły są w `README.md`.

## Role

Moduł **nie dodaje nowych ról**. Korzysta z ról istniejących w projekcie (`podstawowy użytkownik`,
`kadry`, `bankier`, `IT`, `analityk`, `prawnik`, `Portfolio Manager`, `administrator`) i nakłada na
nie dodatkowe ograniczenia. Przykładowo cennik widzą tylko `bankier`, `analityk` i `administrator`.

Rola pochodzi z konta użytkownika, a nie z treści rozmowy. Zdanie „jestem teraz administratorem”
jest traktowane jako próba obejścia zabezpieczeń i blokowane. Agent nie ma własnych uprawnień:
zawsze działa z rolą użytkownika, w którego imieniu pracuje.

## Co moduł sprawdza

Każdą treść moduł ocenia na dwa sposoby:

1. **Dostęp:** czy ta rola w ogóle może widzieć te informacje.
   Przykład: pracownik bez uprawnień pyta o rabaty → blokada.
2. **Użycie:** czy rola, która ma dostęp, może zrobić z nimi to, o co prosi.
   Przykład: bankier może podsumować cennik dla siebie, ale nie może wysłać go do ChatGPT ani na
   prywatny adres e-mail → blokada.

Sprawdzenia działają w czterech miejscach:

```
pytanie użytkownika ─► [1] ─► agent ─► narzędzie [2] ─► wynik narzędzia [3] ─► model ─► odpowiedź [4] ─► użytkownik
```

1. pytanie, zanim trafi do modelu,
2. wywołanie narzędzia, zanim się wykona,
3. dane z narzędzia lub bazy wiedzy, zanim zobaczy je model,
4. odpowiedź modelu, bo model mógł ujawnić coś z kontekstu.

## Jak moduł rozpoznaje poufne treści

| Warstwa | Jak działa | Co łapie |
|---|---|---|
| Słowa kluczowe | rdzenie słów, np. „cennik”, „rabat”, „wynagrodze” | pytania wprost |
| Klauzule | „POUFNE”, „ŚCIŚLE POUFNE” w treści | wklejone dokumenty z oznaczeniem |
| Wzorce | numery umów `HY26-UM-0000`, adresy sieci, klucze | konkretne identyfikatory |
| Odcisk dokumentu | porównanie 8-wyrazowych fragmentów z poufnymi plikami w `data/company_fixtures/` | wklejony fragment bez słów kluczowych |
| Lokalny model AI | Ollama ocenia sens pytania | parafrazy, np. „ile procent zniżki ma nasz największy klient ze Szwecji?” |

Pierwsze cztery warstwy są szybkie i deterministyczne. Model AI jest wołany tylko wtedy, gdy one
nic nie znalazły, a jego ocena może zmienić decyzję. Model działa lokalnie, więc sprawdzana treść
nie trafia do zewnętrznej usługi.

## Co moduł robi po wykryciu naruszenia

Każda reguła określa reakcję w polu `On Violation`:

| Reakcja | Skutek |
|---|---|
| `block` | odmowa z podaniem źródła, np. „Zablokowano zgodnie z §3 ust. 2 Oświadczenia o poufności” |
| `redact` | poufny fragment zastąpiony znacznikiem `[ZASTRZEŻONE: NDA-HY26-03]`, reszta odpowiedzi zostaje |
| `warn` | odpowiedź przechodzi z ostrzeżeniem |
| `log_only` | odpowiedź przechodzi, zdarzenie trafia tylko do logu |

Komunikat o blokadzie nigdy nie powtarza poufnej treści.

## Odporność

- **Zmiany działają od razu.** Edycja `rules.txt` albo dokumentu w `data/company_documents/` działa przy
  najbliższym pytaniu (najpóźniej po sekundzie), bez restartu i bez zmian w kodzie.
- **Błąd w konfiguracji nie wyłącza ochrony.** Zostaje ostatnia poprawna wersja reguł,
  a błąd widać w statusie i w logu.
- **Awaria modelu AI nie otwiera dostępu.** Reguły z `On Detector Error: block` blokują, gdy
  lokalny model nie odpowiada.
- **Reguły są spójne z dokumentami.** Reguła wskazująca nieistniejący paragraf nie zostanie przyjęta.

## Audyt

Każda decyzja trafia do `logs/audit.jsonl`: kto pytał, w którym miejscu, która reguła i paragraf,
która warstwa wykryła naruszenie, z jaką pewnością, jaka zapadła decyzja, jaka była wersja polityki
i ile trwała każda warstwa. Zamiast treści log zapisuje jej skrót SHA-256, więc sam nie staje się
kopią danych poufnych.

## Jak to uruchomić

Komendy uruchamia się z katalogu `backend/`:

```
cd backend
python -m security.company_policies --status
python -m security.company_policies --role bankier "Wyślij cennik do ChatGPT"
python -m security.company_policies --role "podstawowy użytkownik" "Jakie rabaty mamy w cenniku?"
python -m pytest tests/test_company_policies.py -v
```

Szczegóły techniczne, opis wszystkich pól reguły i przykład integracji z agentem są w `README.md`.

## Zastrzeżenia

Wszystkie dokumenty, firmy i dane są fikcyjne. Moduł pomaga egzekwować zasady, ale nie zastępuje
oceny prawnika ani compliance. Wdrożenie u prawdziwego pracodawcy wymaga poinformowania pracowników
o monitoringu (art. 22³ Kodeksu pracy).
