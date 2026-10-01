FROM python:3.11-slim

# Labels & Metadata
LABEL maintainer="ThreatRadar Core Team" \
      description="Autonomous Standalone Cyber Threat Intelligence Hub & SOC Radar" \
      version="1.9.1"

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
    chown -R threatradar:threatradar /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY --chown=threatradar:threatradar . .

# Ensure data directory has proper permissions
RUN chown -R threatradar:threatradar /app/data

# Switch to unprivileged user
USER threatradar

# Expose service port
EXPOSE 9220

# Health check using python standard library
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; sys_exit = 0 if urllib.request.urlopen('http://127.0.0.1:9220/api/status', timeout=3).getcode() == 200 else 1; exit(sys_exit)"

# Launch ThreatRadar server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9220"]
