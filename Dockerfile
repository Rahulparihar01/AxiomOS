# AI-OS Control Plane & Kernel Runtime
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AIOS_LOG_LEVEL=INFO \
    DEFAULT_PROVIDER=mock

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .
RUN pip install --no-cache-dir -e .

# Expose Web Control Center port
EXPOSE 8000

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Persistent volume for SQLite WAL storage
VOLUME ["/app/data"]

# Default entrypoint: Boot kernel with Web Control Center
CMD ["aios", "start", "--web", "--port", "8000"]
