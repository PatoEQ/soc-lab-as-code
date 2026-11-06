# IOC Enricher API — multi-stage, non-root image
ARG PYTHON_IMAGE=python:3.12-slim

# ---------- Stage 1: builder ----------
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install runtime dependencies into an isolated virtual environment,
# then remove pip from it: the final image does not need it
RUN python -m venv /opt/venv
COPY app/requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install -r /tmp/requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip

# ---------- Stage 2: runtime ----------
FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="ioc-enricher" \
      org.opencontainers.image.description="IOC classification and enrichment API for the SOC Lab" \
      org.opencontainers.image.source="https://github.com/PatoEQ/soc-lab-as-code"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Unprivileged user with a fixed UID, no home and no login shell.
# pip is removed so an attacker cannot install tools inside the container.
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && python -m pip uninstall -y pip

WORKDIR /app

# Only the virtual environment travels from the builder stage
COPY --from=builder /opt/venv /opt/venv
# Code stays owned by root: the app user can read it but not modify it
COPY app/ ./app/

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
