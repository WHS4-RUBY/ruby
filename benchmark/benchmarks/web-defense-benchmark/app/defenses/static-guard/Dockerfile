FROM python:3.13-alpine3.23@sha256:7ea3f82de8ea6d4fb7e5d2bbe3fe3c9d931700b7a529f1fe5769e42abe514ca1

WORKDIR /app
COPY server.py /app/server.py
RUN adduser -D -u 10003 defense
USER defense
EXPOSE 8080 8081
ENTRYPOINT ["python", "/app/server.py"]
