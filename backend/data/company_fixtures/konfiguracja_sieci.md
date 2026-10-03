ŚCIŚLE POUFNE

# Fragment konfiguracji sieci magazynu Stryków

> Dokument FIKCYJNY, przygotowany wyłącznie na potrzeby demonstracji AI Control Layer.
> Firma, osoby, kwoty i adresy są wymyślone.

```
vlan 120 name SKANERY  subnet 10.20.120.0/24
vlan 130 name KAMERY   subnet 10.20.130.0/24
firewall rule 17: allow 10.20.120.0/24 -> 10.20.5.14:8443 (HackTMS API)
wifi psk: HY26-PSK-7Q2X-DEMO
```

Dostęp administracyjny do przełączników rdzeniowych odbywa się wyłącznie przez serwer przesiadkowy w sieci zarządzającej.
