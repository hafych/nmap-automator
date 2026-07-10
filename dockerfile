FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_HOST=0.0.0.0 \
    RESULTS_DIR=/app/encrypted_results \
    SCAN_LOG_PATH=/app/logs/scan_log.txt

RUN apt-get update \
    && apt-get install --no-install-recommends -y nmap \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 app

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install -r requirements.txt

COPY --chown=app:app . .
RUN mkdir -p encrypted_results logs \
    && chown -R app:app encrypted_results logs

USER app
EXPOSE 5000
VOLUME ["/app/encrypted_results", "/app/logs"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3)"]

STOPSIGNAL SIGTERM
CMD ["python", "autonmap.py"]
