# Backend: Demo app API, dashboard, metrics, and OpenAI-compatible proxy in a single process (python main.py).
#
# Directory layout mirrors repo (/repo/backend, /repo/policy) for relative path resolution.
# PII and refusal models are pre-downloaded in the image for offline readiness.
FROM python:3.12-slim

# CPU version of PyTorch to avoid heavy CUDA runtime dependencies
ARG TORCH_INDEX=https://download.pytorch.org/whl/cpu
ARG PII_MODEL=urchade/gliner_small-v2.1
ARG REFUSAL_MODEL=sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/models \
    PII_MODEL=${PII_MODEL} \
    REFUSAL_MODEL=${REFUSAL_MODEL}

# Dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --index-url "${TORCH_INDEX}" "$(grep -E '^torch==' /tmp/requirements.txt)" \
 && pip install -r /tmp/requirements.txt


# Models baked into image (separate layer: doesn't rebuild on code changes).
RUN python -c "import os; \
from gliner import GLiNER; GLiNER.from_pretrained(os.environ['PII_MODEL']); \
from sentence_transformers import SentenceTransformer; SentenceTransformer(os.environ['REFUSAL_MODEL']); \
from huggingface_hub import snapshot_download; snapshot_download(os.environ['REFUSAL_MODEL'], allow_patterns=['tokenizer.json'])"

# Non-root user; /state for audit logs, databases and policy overrides (volume).
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
