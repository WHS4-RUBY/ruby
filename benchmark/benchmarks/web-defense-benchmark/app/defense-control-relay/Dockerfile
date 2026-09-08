FROM python:3.13-alpine3.23@sha256:7ea3f82de8ea6d4fb7e5d2bbe3fe3c9d931700b7a529f1fe5769e42abe514ca1

WORKDIR /app
COPY relay.py /app/relay.py
RUN adduser -D -u 10004 relay
USER relay
EXPOSE 8080
ENTRYPOINT ["python", "/app/relay.py"]
