# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    whois \
    curl \
    wget \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create directories for logs and reports
RUN mkdir -p /app/logs /app/reports /app/config

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -u 1000 recon && \
    chown -R recon:recon /app

# Switch to non-root user
USER recon

# Set default command
ENTRYPOINT ["python", "main.py"]

# Default help command
CMD ["--help"]

# Expose port for any future web interface
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Labels for metadata
LABEL maintainer="Security Research Team"
LABEL version="1.0.0"
LABEL description="CyberRecon - Comprehensive Reconnaissance Tool"
LABEL org.opencontainers.image.source="https://github.com/your-org/cyberrecon"