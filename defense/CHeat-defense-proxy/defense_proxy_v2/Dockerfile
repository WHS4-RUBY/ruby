FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UVICORN_PROXY_HEADERS=0 \
    DEFENSE_DB=/data/defense.db

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir -p /data \
    && chown 10001:10001 /data

# The administrative dashboard is a separate application and is deliberately
# absent from the production sidecar image.
COPY Defense_proxy.py proxy_core.py transforms.py profiles.py preflight.py store.py ./
USER 10001:10001

EXPOSE 3012
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD python -c "import socket; socket.create_connection(('127.0.0.1', 3012), 2).close()"
CMD ["uvicorn", "Defense_proxy:app", "--host", "0.0.0.0", "--port", "3012", "--no-proxy-headers", "--no-server-header"]
