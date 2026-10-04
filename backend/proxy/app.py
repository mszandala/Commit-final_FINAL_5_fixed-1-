"""HTTP: POST /v1/chat/completions (zgodne z OpenAI) i GET /v1/models."""
import json
import logging
from typing import Callable

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from core import PolicyError

from .engine import ProxyEngine, ProxyError

log = logging.getLogger("control_layer.proxy")


def _error(status: int, message: str, code: str = "invalid_request_error", headers: dict = None) -> JSONResponse:
    return JSONResponse(status_code=status, headers=headers or {},
                        content={"error": {"message": message, "type": code, "code": code}})


def create_router(get_engine: Callable[[], ProxyEngine]) -> APIRouter:
    """Router proxy; silnik tworzony leniwie, więc błędny plik polityki daje 503 zamiast awarii przy starcie."""
    router = APIRouter(tags=["proxy"])

    @router.post("/v1/chat/completions", summary="Czat zgodny z OpenAI, przechodzący przez warstwę bezpieczeństwa",
                 description="Zmień w aplikacji tylko base_url i klucz API; rolę wyznacza klucz (sekcja `clients` "
                             "w pliku polityki). Odpowiedź ma dodatkowe pole `x_security` z decyzją i śladem, a "
                             "nagłówki X-Session-Id, X-Security-Decision i X-Policy-Version. Rozmowę łączy "
                             "X-Session-Id (bez niego: skrót klucza i pierwszej wiadomości). Streaming: jeszcze nie.")
    async def chat_completions(request: Request):
        try:
            engine = get_engine()
            client = engine.authenticate(request.headers.get("Authorization"))
            limit = engine.policy().proxy.max_body_bytes
            declared = request.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > limit:
                return _error(413, f"The request body is larger than {limit} bytes")
            body = await request.body()
            if len(body) > limit:
                return _error(413, f"The request body is larger than {limit} bytes")
            try:
                payload = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                return _error(400, "The request body is not valid JSON")
            result = await run_in_threadpool(engine.complete, client, payload, request.headers.get("X-Session-Id"))
            return JSONResponse(result.body, headers=result.headers)
        except ProxyError as exc:
            return _error(exc.status, exc.message, exc.code,
                          {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None)
        except PolicyError as exc:
            log.error("Policy file is invalid: %s", exc)
            return _error(503, "The policy file is invalid; see GET /api/v1/policy", "policy_error")
        except Exception as exc:
            log.exception("Proxy request failed")
            return _error(500, f"Internal error ({type(exc).__name__})", "internal_error")

    @router.get("/v1/models", summary="Modele dozwolone przez politykę")
    async def models(request: Request):
        try:
            engine = get_engine()
            engine.authenticate(request.headers.get("Authorization"))
            return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "upstream"}
                                               for m in engine.models()]}
        except ProxyError as exc:
            return _error(exc.status, exc.message, exc.code)
        except PolicyError:
            return _error(503, "The policy file is invalid; see GET /api/v1/policy", "policy_error")

    return router
