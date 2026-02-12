#!/bin/bash
# Docker entrypoint script for AI Cyber Battlefield application

set -e

echo "=========================================="
echo "AI Cyber Battlefield - Startup Script"
echo "=========================================="
echo ""

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
while ! pg_isready -h postgres -U ${DB_USER:-cyber_user} -d ${DB_NAME:-cyber_battlefield}; do
    echo "  PostgreSQL is unavailable - sleeping"
    sleep 2
done
echo "PostgreSQL is ready!"

# Wait for Redis to be ready
echo "Waiting for Redis to be ready..."
for i in {1..30}; do
    if redis-cli -h redis -p 6379 --raw incr ping > /dev/null 2>&1; then
        echo "Redis is ready!"
        break
    fi
    echo "  Redis is unavailable - sleeping ($i/30)"
    sleep 1
done

# Wait for Ollama to be ready
echo "Waiting for Ollama to be ready..."
for i in {1..60}; do
    if curl -s http://ollama:11434/api/tags > /dev/null 2>&1; then
        echo "Ollama is ready!"
        break
    fi
    echo "  Ollama is unavailable - sleeping ($i/60)"
    sleep 2
done

# Create logs directory if it doesn't exist
mkdir -p /app/logs
mkdir -p /app/results

# Change ownership to non-root user
if id "cyberuser" &>/dev/null; then
    chown -R cyberuser:cyberuser /app/logs
    chown -R cyberuser:cyberuser /app/results
fi

echo ""
echo "=========================================="
echo "All services are ready!"
echo "Starting application..."
echo "=========================================="
echo ""

# Execute the main application
exec "$@"
