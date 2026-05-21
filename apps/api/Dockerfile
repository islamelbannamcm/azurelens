# AzureLens API — production-style image (Phase 9 demo).
#
# Multi-stage:
#   1. builder — installs Python deps + project package into a venv
#   2. runtime — minimal slim image with the venv + non-root user
#
# In Phase 1+ secrets come from Azure Key Vault via Managed Identity.
# NEVER bake secrets into this image. NEVER read `.env` at runtime in
# non-local environments.

# --------------------------------------------------------------------------
# Stage 1: builder
# --------------------------------------------------------------------------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Build deps (kept out of runtime).
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

# Project-local venv so the runtime stage copies a single tree.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY pyproject.toml README.md ./
COPY app ./app

RUN pip install --upgrade pip \
 && pip install .

# --------------------------------------------------------------------------
# Stage 2: runtime
# --------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    AZURELENS_ENV=local

# Non-root user (uid/gid 10001).
RUN groupadd --gid 10001 app \
 && useradd  --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY app ./app

USER 10001

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=4 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health',timeout=2).status==200 else 1)"

# Single-process uvicorn; horizontal scale is the orchestrator's job
# (Container Apps replicas / App Service instance count).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
