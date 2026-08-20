FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY cheat/ ./cheat/
RUN pip install --no-cache-dir -e .
CMD ["/bin/bash"]
