# IOCReaper Dockerfile - Phase 5 Security Enhanced
# Multi-stage build for optimized and secure container

# ============================================================================
# Builder Stage
# ============================================================================
FROM python:3.11-slim as builder

LABEL maintainer="Manudeep Maddipatla <mmaddipa@umd.edu>"
LABEL description="IOCReaper - Secure IOC Extraction Tool"
LABEL version="2.0.0"

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY app/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# ============================================================================
# Final Stage
# ============================================================================
FROM python:3.11-slim

WORKDIR /app

# Create non-root user for security
RUN groupadd -r iocreaper && \
    useradd -r -g iocreaper -u 1000 -m -s /sbin/nologin iocreaper && \
    mkdir -p /app/logs && \
    chown -R iocreaper:iocreaper /app

# Copy Python dependencies from builder
COPY --from=builder /root/.local /home/iocreaper/.local

# Copy application files
COPY --chown=iocreaper:iocreaper app/ ./app/
COPY --chown=iocreaper:iocreaper static/ ./static/
COPY --chown=iocreaper:iocreaper templates/ ./templates/

# Create and set permissions for logs directory
RUN mkdir -p logs && chown -R iocreaper:iocreaper logs

# Switch to non-root user
USER iocreaper

# Set PATH to include user's local bin
ENV PATH=/home/iocreaper/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run the application
CMD ["python", "app/main.py"]
