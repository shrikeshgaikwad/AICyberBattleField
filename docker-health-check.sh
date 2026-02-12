#!/bin/bash
# Health check script for AI Cyber Battlefield Docker environment

set -e

echo "=========================================="
echo "AI Cyber Battlefield - Health Check"
echo "=========================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is running
echo "Checking Docker daemon..."
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}✗${NC} Docker daemon is not running"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker daemon is running"
echo ""

# Check if docker-compose is available
echo "Checking docker-compose..."
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}✗${NC} docker-compose is not installed"
    exit 1
fi
echo -e "${GREEN}✓${NC} docker-compose is installed"
echo ""

# Check if .env file exists
echo "Checking .env configuration..."
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠${NC}  .env file not found. Creating from .env.example..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo -e "${GREEN}✓${NC} .env created (please review and update passwords)"
    else
        echo -e "${RED}✗${NC} .env.example not found"
        exit 1
    fi
else
    echo -e "${GREEN}✓${NC} .env file exists"
fi
echo ""

# Check containers status
echo "Checking container status..."
echo ""

containers=(
    "ollama_service"
    "cyber_db"
    "cyber_redis"
    "cyber_battle_app"
)

all_healthy=true

for container in "${containers[@]}"; do
    if docker-compose ps $container 2>/dev/null | grep -q "running"; then
        # Check health status if available
        health=$(docker-compose ps $container 2>/dev/null | grep -o "healthy\|unhealthy" || echo "running")
        echo -e "${GREEN}✓${NC} $container: $health"
    else
        echo -e "${RED}✗${NC} $container: not running"
        all_healthy=false
    fi
done
echo ""

# Check port availability
echo "Checking port availability..."
echo ""

ports_check=(
    "11434:Ollama"
    "5432:PostgreSQL"
    "6379:Redis"
    "8000:App (primary)"
    "8080:App (secondary)"
    "5050:pgAdmin"
)

for port_info in "${ports_check[@]}"; do
    port=${port_info%:*}
    service=${port_info#*:}
    
    if nc -z localhost $port 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Port $port ($service): Open"
    else
        echo -e "${YELLOW}⚠${NC}  Port $port ($service): Not reachable"
    fi
done
echo ""

# Check service health endpoints
echo "Testing service endpoints..."
echo ""

# Test Ollama
echo -n "Testing Ollama API... "
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}✗${NC}"
fi

# Test PostgreSQL
echo -n "Testing PostgreSQL... "
if docker-compose exec -T postgres pg_isready -U cyber_user 2>/dev/null | grep -q "accepting"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}✗${NC}"
fi

# Test Redis
echo -n "Testing Redis... "
if docker-compose exec -T redis redis-cli ping 2>/dev/null | grep -q "PONG"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}✗${NC}"
fi

echo ""

# Container resource usage
echo "Container resource usage:"
echo ""
docker stats --no-stream --format "table {{.Container}}\t{{.MemUsage}}\t{{.CPUPerc}}" 2>/dev/null | grep -E "cyber_|ollama_" || true
echo ""

# Summary
echo "=========================================="
if [ "$all_healthy" = true ]; then
    echo -e "${GREEN}✓ All services appear to be healthy!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. View logs: docker-compose logs -f"
    echo "2. Access app: docker-compose exec cyber_battle bash"
    echo "3. Check database: docker-compose exec postgres psql -U cyber_user -d cyber_battlefield"
    echo "4. View full guide: cat DOCKER_GUIDE.md"
else
    echo -e "${RED}✗ Some services are not healthy${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "1. Check logs: docker-compose logs"
    echo "2. Restart containers: docker-compose restart"
    echo "3. Rebuild: docker-compose down -v && docker-compose up -d"
fi
echo "=========================================="
