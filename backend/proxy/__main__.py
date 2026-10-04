"""Narzędzie pomocnicze: python -m proxy hash-key <klucz>  |  python -m proxy new-key [nazwa] [rola]"""
import sys

from proxy.keys import hash_key, new_key

USAGE = "użycie: python -m proxy hash-key <klucz>  |  python -m proxy new-key [nazwa] [rola]"


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "hash-key":
        print(hash_key(argv[1]))
        return 0
    if argv and argv[0] == "new-key":
        key = new_key()
        name = argv[1] if len(argv) > 1 else "nowy-klient"
        role = argv[2] if len(argv) > 2 else "podstawowy użytkownik"
        print(f"Klucz (pokaż go klientowi i nigdzie nie zapisuj): {key}")
        print("Wpis do sekcji `clients` w pliku polityki:")
        print(f'  - {{name: {name}, role: "{role}", key_sha256: {hash_key(key)}}}')
        return 0
    print(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
