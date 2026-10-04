"""API server entrypoint: python main.py (from backend/ directory). Docs: http://127.0.0.1:8000/docs"""
import os

import uvicorn

# Inject system certificate store via truststore if available to handle custom corporate root CAs.
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

if __name__ == "__main__":
    uvicorn.run("api.app:app", host=os.getenv("API_HOST", "127.0.0.1"), port=int(os.getenv("API_PORT", "8000")))
