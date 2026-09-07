FROM python:3.13-alpine3.23@sha256:7ea3f82de8ea6d4fb7e5d2bbe3fe3c9d931700b7a529f1fe5769e42abe514ca1

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt ./
RUN apk upgrade --no-cache \
    && pip install --no-cache-dir -r requirements.txt \
    && python -m pip uninstall -y pip setuptools \
    && rm -rf /usr/local/lib/python3.13/ensurepip \
    && adduser -D -u 10001 appuser
COPY ruby_mock ./ruby_mock

USER appuser
CMD ["uvicorn", "ruby_mock.main:app", "--host", "0.0.0.0", "--port", "8000"]
