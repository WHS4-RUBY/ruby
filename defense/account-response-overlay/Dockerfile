FROM python:3.14-slim
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock \
    && groupadd --gid 10001 defense \
    && useradd --uid 10001 --gid defense --no-create-home defense \
    && mkdir /app/state && chown defense:defense /app/state
COPY defense ./defense
COPY config ./config
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
ENTRYPOINT ["python", "-m", "defense.overlay_bootstrap"]
