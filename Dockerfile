FROM python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

# Labels & Metadata
LABEL maintainer="ThreatRadar Core Team" \
      description="Autonomous Standalone Cyber Threat Intelligence Hub & SOC Radar" \
      version="1.17.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BASE_DIR=/app \
    DB_PATH=/app/data/threat_radar.db \
    HOST=0.0.0.0 \
    PORT=9220

# Create working directory and non-root user
WORKDIR /app

RUN groupadd -g 10001 threatradar && \
    useradd -u 10001 -g threatradar -s /bin/bash -m threatradar && \
    mkdir -p /app/data && \
    chown threatradar:threatradar /app/data

# Install dependencies
COPY requirements-prod.lock .
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir pip==26.2.1 && \
    pip install --no-cache-dir --require-hashes -r requirements-prod.lock && \
    pip uninstall --yes setuptools wheel && \
    python -m pip uninstall --yes pip && \
    rm -rf /usr/local/lib/python3.12/ensurepip

# Copy application source code
COPY . .

# Ensure data directory has proper permissions
RUN chown -R threatradar:threatradar /app/data && \
    chmod -R a-w /app/app /app/scripts && \
    chmod 0750 /app/data

# Switch to unprivileged user
USER threatradar

# Expose service port
EXPOSE 9220

# Health check using python standard library
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; sys_exit = 0 if urllib.request.urlopen('http://127.0.0.1:9220/api/status', timeout=3).getcode() == 200 else 1; exit(sys_exit)"

# Launch ThreatRadar server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9220", "--no-server-header"]
