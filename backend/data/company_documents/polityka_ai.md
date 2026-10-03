# Polityka korzystania z narzędzi AI w HackYeah2026

> Dokument FIKCYJNY, przygotowany wyłącznie na potrzeby demonstracji AI Control Layer.
> Firma, osoby, kwoty i adresy są wymyślone.

## §1. Cel

1. Polityka określa zasady korzystania z modeli językowych i agentów AI przez pracowników Spółki.

## §2. Dane w zewnętrznych modelach

<!-- control: AI-HY26-02 -->
1. Zakazane jest wprowadzanie informacji poufnych i ściśle poufnych do zewnętrznych modeli językowych i zewnętrznych API, a także wysyłanie ich na adresy spoza domeny hackyeah2026.test.

## §3. Dozwolone modele

1. Informacje wewnętrzne i poufne można przetwarzać wyłącznie w modelach uruchomionych lokalnie, wymienionych w centralnej konfiguracji polityk (pole „Allowed Models”).
2. Modele zewnętrzne mogą przetwarzać wyłącznie informacje publiczne.

## §4. Agenci AI

1. Agent działa wyłącznie z uprawnieniami użytkownika, w którego imieniu wykonuje zadanie, i nie może ich rozszerzać.
2. Nieodwracalne akcje agentów (np. wysyłka, usunięcie, płatność) wymagają zatwierdzenia przez człowieka.

## §5. Obchodzenie zabezpieczeń

<!-- control: AI-HY26-05 -->
1. Zakazane jest obchodzenie zabezpieczeń asystenta AI, w szczególności przez prompt injection i podawanie się za osobę o innej roli lub szerszych uprawnieniach.
