# Multi-stage build for production Flask-RESTX application with Poetry

# Stage 1: Builder
FROM python:3.10.12-alpine AS builder

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.7.1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

# Add poetry to PATH
ENV PATH="$POETRY_HOME/bin:$PATH"

# Install system dependencies for building Python packages
RUN apk add --no-cache \
    curl \
    gcc \
    musl-dev \
    linux-headers \
    libffi-dev \
    openssl-dev \
    python3-dev \
    build-base

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies
RUN poetry lock --no-update && \
    poetry install --only main --no-root && \
    poetry cache clear pypi --all

# Stage 2: Runtime
FROM python:3.10.12-alpine

# Create non-root user for security
RUN addgroup -g 1000 -S appuser && \
    adduser -u 1000 -S appuser -G appuser

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    FLASK_DEBUG=0 \
    PATH="/app/.venv/bin:$PATH"

# Install runtime dependencies only
RUN apk add --no-cache \
    curl \
    libffi \
    libgcc \
    libstdc++ && \
    rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv

# Copy application code
COPY --chown=appuser:appuser src/ /app/src/

# Create instance directory for SQLite database
RUN mkdir -p /app/instance && \
    chown -R appuser:appuser /app

# Create entrypoint script
RUN echo '#!/bin/sh' > /app/entrypoint.sh && \
    echo 'set -e' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# Initialize admin user if needed' >> /app/entrypoint.sh && \
    echo 'if [ "$INIT_ADMIN" = "true" ]; then' >> /app/entrypoint.sh && \
    echo '    echo "Initializing admin user..."' >> /app/entrypoint.sh && \
    echo '    python /app/src/init_admin.py' >> /app/entrypoint.sh && \
    echo 'fi' >> /app/entrypoint.sh && \
    echo '' >> /app/entrypoint.sh && \
    echo '# Start the application' >> /app/entrypoint.sh && \
    echo 'echo "Starting Firewall Manager API..."' >> /app/entrypoint.sh && \
    echo 'exec gunicorn --bind 0.0.0.0:5000 --workers ${WORKERS:-4} --threads ${THREADS:-2} --timeout 120 --access-logfile - --error-logfile - "src.app:create_app()"' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh && \
    chown appuser:appuser /app/entrypoint.sh

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# Run the application
ENTRYPOINT ["/app/entrypoint.sh"]