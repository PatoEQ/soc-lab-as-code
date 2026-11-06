# IOC Enricher API — Phase 2, single-stage image (hardened on day 3)
FROM python:3.12-slim

# Python settings for containers:
#   PYTHONDONTWRITEBYTECODE  do not write .pyc files
#   PYTHONUNBUFFERED         send logs straight to stdout (docker logs)
#   PIP_NO_CACHE_DIR         do not keep pip's download cache in the image
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first: this layer is reused until requirements.txt changes
COPY app/requirements.txt ./app/requirements.txt
RUN pip install -r app/requirements.txt

# Application code last: it changes most often
COPY app/ ./app/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
