# Docker Commands for AI Cyber Battlefield

.PHONY: help build up down logs clean rebuild test

help:
	@echo "AI Cyber Battlefield - Docker Commands"
	@echo "========================================"
	@echo ""
	@echo "Development Commands:"
	@echo "  make build          - Build Docker images"
	@echo "  make up             - Start all containers"
	@echo "  make down           - Stop all containers"
	@echo "  make logs           - View container logs"
	@echo "  make clean          - Remove containers and volumes"
	@echo "  make rebuild        - Rebuild and restart"
	@echo "  make shell          - Open shell in cyber_battle container"
	@echo "  make db-shell       - Open PostgreSQL shell"
	@echo ""
	@echo "Production Commands:"
	@echo "  make prod-up        - Start production environment"
	@echo "  make prod-down      - Stop production environment"
	@echo "  make prod-logs      - View production logs"
	@echo ""
	@echo "Database Commands:"
	@echo "  make db-migrate     - Initialize database"
	@echo "  make db-reset       - Reset database"
	@echo "  make db-backup      - Backup database"
	@echo ""
	@echo "Monitoring:"
	@echo "  make ps             - Show running containers"
	@echo "  make stats          - Show container stats"
	@echo "  make health         - Check container health"

build:
	docker-compose build

up:
	docker-compose up -d
	@echo "Waiting for services to start..."
	@sleep 5
	docker-compose ps

down:
	docker-compose down

logs:
	docker-compose logs -f

logs-app:
	docker-compose logs -f cyber_battle

logs-db:
	docker-compose logs -f postgres

logs-ollama:
	docker-compose logs -f ollama

clean:
	docker-compose down -v
	@echo "Cleaned all containers and volumes"

rebuild:
	docker-compose down -v
	docker-compose build --no-cache
	docker-compose up -d
	@echo "Rebuild complete"

shell:
	docker-compose exec cyber_battle /bin/bash

db-shell:
	docker-compose exec postgres psql -U cyber_user -d cyber_battlefield

prod-up:
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

prod-down:
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml down

prod-logs:
	docker-compose -f docker-compose.yml -f docker-compose.prod.yml logs -f

db-migrate:
	docker-compose up -d postgres
	@echo "Waiting for database to be ready..."
	@sleep 10
	docker-compose up -d

db-reset:
	docker-compose exec postgres psql -U cyber_user -d cyber_battlefield -c "DROP SCHEMA cyber_data CASCADE; DROP SCHEMA logs CASCADE;"
	@echo "Schemas dropped. Recreating..."
	docker-compose restart postgres

db-backup:
	docker-compose exec -T postgres pg_dump -U cyber_user cyber_battlefield > backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "Database backed up"

ps:
	docker-compose ps

stats:
	docker stats

health:
	@echo "Checking container health..."
	docker-compose ps --format "table {{.Names}}\t{{.Status}}"

test:
	docker-compose exec cyber_battle python -m pytest tests/

test-coverage:
	docker-compose exec cyber_battle python -m pytest tests/ --cov=.

lint:
	docker-compose exec cyber_battle python -m pylint **/*.py

format:
	docker-compose exec cyber_battle python -m black .

install-models:
	docker-compose exec ollama ollama pull llama2:13b
	docker-compose exec ollama ollama pull mistral:latest

pull-models:
	docker-compose exec ollama ollama pull $${MODEL:-llama2:13b}

list-models:
	docker-compose exec ollama ollama list

network-inspect:
	docker network inspect cyber_network

volume-prune:
	docker volume prune -f

image-prune:
	docker image prune -f

system-prune:
	docker system prune -f

push-registry:
	docker-compose push

.PHONY: help build up down logs logs-app logs-db logs-ollama clean rebuild shell db-shell prod-up prod-down prod-logs db-migrate db-reset db-backup ps stats health test test-coverage lint format install-models pull-models list-models network-inspect volume-prune image-prune system-prune push-registry
