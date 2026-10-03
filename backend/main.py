"""Start serwera API: python main.py (z katalogu backend/). Dokumentacja: http://127.0.0.1:8000/docs"""
import os

import uvicorn

# Na komputerach, gdzie antywirus lub firmowe proxy podmienia certyfikaty HTTPS, Python odrzuca
# połączenie z dostawcą modelu. Jeśli pakiet truststore jest zainstalowany, używamy magazynu
# certyfikatów systemu; weryfikacja certyfikatów pozostaje włączona.
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

if __name__ == "__main__":
    uvicorn.run("api.app:app", host=os.getenv("API_HOST", "127.0.0.1"), port=int(os.getenv("API_PORT", "8000")))
