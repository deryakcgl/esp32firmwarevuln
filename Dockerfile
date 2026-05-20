# syntax=docker/dockerfile:1
# Linux image with Python deps for ELF + source analysis.

FROM python:3.12-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "esp32_firmguard.cli", "--help"]
