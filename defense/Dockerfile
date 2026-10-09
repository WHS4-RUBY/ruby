FROM python:3.12-slim
WORKDIR /app
# SQLite is the default alias store. Build with --build-arg WITH_POSTGRES=true to add the
# optional PostgreSQL driver for PATH_ALIAS_DB_URL.
ARG WITH_POSTGRES=false
COPY requirements.txt requirements-postgres.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$WITH_POSTGRES" = "true" ]; then pip install --no-cache-dir -r requirements-postgres.txt; fi
COPY app ./app
COPY config ./config
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers"]
