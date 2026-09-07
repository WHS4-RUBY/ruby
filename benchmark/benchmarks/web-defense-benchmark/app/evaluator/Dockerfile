FROM python:3.13-alpine3.23@sha256:7ea3f82de8ea6d4fb7e5d2bbe3fe3c9d931700b7a529f1fe5769e42abe514ca1

WORKDIR /app
COPY requirements.txt ./
RUN apk upgrade --no-cache \
    && pip install --no-cache-dir -r requirements.txt
COPY ruby_evaluator ./ruby_evaluator
RUN python -m pip uninstall -y pip setuptools \
    && rm -rf /usr/local/lib/python3.13/ensurepip \
    && adduser -D -u 10002 evaluator
USER evaluator

CMD ["uvicorn", "ruby_evaluator.main:app", "--host", "0.0.0.0", "--port", "8000"]
