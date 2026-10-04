# Backend: API aplikacji demo, panel, metryki i proxy zgodne z OpenAI w jednym procesie (python main.py).
#
# Układ katalogów odtwarza repozytorium (/repo/backend, /repo/policy), bo kod i testy liczą ścieżki
# względem niego. Modele PII i wykrywania odmów są wbudowane w obraz, więc kontener działa bez internetu
# (poza wywołaniami modelu językowego).
FROM python:3.12-slim

# Wersja CPU biblioteki torch: domyślne koło dla Linuksa ciągnie GPU i kilka GB bibliotek CUDA.
ARG TORCH_INDEX=https://download.pytorch.org/whl/cpu
ARG PII_MODEL=urchade/gliner_small-v2.1
ARG REFUSAL_MODEL=sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/models \
    PII_MODEL=${PII_MODEL} \
    REFUSAL_MODEL=${REFUSAL_MODEL}

# Zależności. Pomijamy chromadb, kubernetes i onnxruntime: używa ich tylko narzędzie RAG
# (tools/rag.py), którego aplikacja nie ładuje, a razem ważą setki MB.
COPY requirements.txt /tmp/requirements.txt
RUN grep -vE '^(chromadb|kubernetes|onnxruntime)==' /tmp/requirements.txt > /tmp/app-requirements.txt \
 && pip install --index-url "${TORCH_INDEX}" "$(grep -E '^torch==' /tmp/app-requirements.txt)" \
 && pip install -r /tmp/app-requirements.txt

# Modele do obrazu (osobna warstwa: nie przebudowuje się przy zmianie kodu).
RUN python -c "import os; \
from gliner import GLiNER; GLiNER.from_pretrained(os.environ['PII_MODEL']); \
from sentence_transformers import SentenceTransformer; SentenceTransformer(os.environ['REFUSAL_MODEL']); \
from huggingface_hub import snapshot_download; snapshot_download(os.environ['REFUSAL_MODEL'], allow_patterns=['tokenizer.json'])"

# Użytkownik bez uprawnień roota; /state na log audytu, bazy i nadpisania polityki (wolumen).
RUN useradd --system --uid 10001 --home-dir /nonexistent --no-create-home app \
 && install -d -o 10001 -g 10001 /state \
 && install -d -o 10001 -g 10001 -m 0700 /run/executor \
 && chown -R 10001:10001 /models

COPY --chown=10001:10001 backend/ /repo/backend/
COPY --chown=10001:10001 policy/ /repo/policy/

WORKDIR /repo/backend
USER 10001:10001

ENV API_HOST=0.0.0.0 \
    API_PORT=8000 \
    STATE_DIR=/state \
    POLICY_FILE=/repo/policy/policy.yaml \
    POLICY_OVERRIDES_FILE=/state/policy.overrides.json \
    COMPANY_POLICIES_AUDIT_LOG=/state/company_policies_audit.jsonl

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/v1/health' % os.environ['API_PORT'], timeout=4)"

CMD ["python", "main.py"]
