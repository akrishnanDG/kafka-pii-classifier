FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies for confluent-kafka (librdkafka)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc librdkafka-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (cached layer)
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ src/
COPY tests/ tests/

# Install the package
RUN pip install --no-cache-dir -e .

# Create non-root user
RUN useradd --create-home appuser
USER appuser

# Create directories for reports and backups
RUN mkdir -p /home/appuser/reports /home/appuser/schema_backups

# Default: show help
ENTRYPOINT ["pii-classifier"]
CMD ["--help"]

# Health check for API server mode
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1
