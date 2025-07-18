# Multi-stage build for SecDash v2.0 backend
FROM python:3.11-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    docker.io \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and add to docker group
RUN useradd --create-home --shell /bin/bash app && \
    usermod -aG docker app

# Set working directory
WORKDIR /app

# Copy Python packages from builder to both user and system locations
COPY --from=builder /root/.local /root/.local
COPY --from=builder /root/.local /home/app/.local

# Copy application code
COPY . .

# Change ownership to app user
RUN chown -R app:app /app

# Add local Python packages to PATH for both root and app user
ENV PATH=/home/app/.local/bin:/root/.local/bin:$PATH
ENV PYTHONPATH=/app

# Switch to non-root user by default
USER app

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

# Expose port
EXPOSE 8000

# Default command (can be overridden)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
