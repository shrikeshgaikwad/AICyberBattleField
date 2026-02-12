# Docker Setup Guide for AI Cyber Battlefield

## Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+

## Quick Start

### 1. Setup Environment Variables
```bash
cp .env.example .env
# Edit .env and add your API keys
```

### 2. Build and Run
```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f cyber_battle

# View Ollama service logs
docker-compose logs -f ollama
```

### 3. Pull the LLM Model (First Time)
The first time you run Ollama, you need to pull the model:

```bash
# Option 1: Using docker-compose exec
docker-compose exec ollama ollama pull llama3.1:8b

# Option 2: Using docker exec
docker exec ollama_service ollama pull llama3.1:8b
```

Alternatively, uncomment the `command` section in docker-compose.yml to auto-pull on startup.

### 4. Stop Services
```bash
docker-compose down

# Remove volumes (warning: deletes data)
docker-compose down -v
```

## Architecture

### Services
- **ollama**: LLM service (Ollama with llama3.1:8b model)
  - Port: 11434
  - Persistence: `ollama_data` volume

- **cyber_battle**: Main application
  - Runs AI Cyber Battlefield analysis
  - Depends on Ollama service
  - Mounts local directory for development

### Volumes
- `ollama_data`: Stores Ollama cache and models
- `cyber_results`: Stores analysis results

### Network
- All services communicate via `cyber_network` bridge network

## Development Mode

### Interactive Development
```bash
# Start in interactive mode with bash
docker-compose run --rm cyber_battle bash

# Run inside container
python main.py
```

### Hot Reload
The docker-compose.yml mounts the current directory to `/app` in the container, allowing you to:
1. Edit files on your host machine
2. Changes are automatically reflected in the container
3. Re-run the application to see changes

### Debugging
```bash
# Connect to running container
docker-compose exec cyber_battle bash

# Install additional packages
docker-compose exec cyber_battle pip install package_name

# Run Python interactive shell
docker-compose exec cyber_battle python
```

## Production Considerations

### Security
- Non-root user (`cyberuser`) runs the app
- Use strong passwords if enabling database
- Manage API keys through secure .env configuration

### Performance
- Ollama can use significant memory (8GB+ recommended for llama3.1:8b)
- Adjust CPU/memory limits in docker-compose.yml if needed
- Use named volumes for persistence

### Persistence (Optional)
Uncomment the `database` service in docker-compose.yml to add PostgreSQL:
```yaml
database:
  image: postgres:15-alpine
  environment:
    POSTGRES_USER: cyber_user
    POSTGRES_PASSWORD: your_secure_password
    POSTGRES_DB: cyber_battlefield
```

## Troubleshooting

### Ollama service won't start
```bash
# Check Ollama logs
docker-compose logs ollama

# Ensure port 11434 is not in use
netstat -an | grep 11434
```

### Main app can't connect to Ollama
```bash
# Check network connectivity
docker-compose exec cyber_battle ping ollama

# Verify Ollama API
curl http://localhost:11434/api/tags
```

### Out of memory
```bash
# Check resource usage
docker stats

# Limit container memory in docker-compose.yml
deploy:
  resources:
    limits:
      memory: 4G
```

### Model not found
```bash
# List available models in Ollama
docker-compose exec ollama ollama list

# Pull required model
docker-compose exec ollama ollama pull llama3.1:8b
```

## Advanced Configuration

### Custom Docker Compose Override
Create `docker-compose.override.yml` for local overrides:
```yaml
version: '3.8'
services:
  ollama:
    ports:
      - "11434:11434"
  cyber_battle:
    environment:
      - DEBUG=true
    command: python -m pdb main.py
```

### Building Custom Images
```bash
# Build with custom tags
docker build -t cyber-battle:v1.0 .

# Build without cache
docker build --no-cache -t cyber-battle:latest .
```

## Resource Optimization

For systems with limited resources, consider:
1. Using smaller Ollama models (e.g., `mistral:7b`)
2. Removing the database service
3. Adjusting memory limits

## Useful Commands

```bash
# View all containers
docker ps -a

# View all volumes
docker volume ls

# Inspect service configuration
docker-compose config

# Validate docker-compose.yml
docker-compose config --quiet

# Clean up unused resources
docker system prune

# View container resource usage
docker stats cyber_battle

# Get container IP address
docker inspect cyber_battle | grep IPAddress
```

## Next Steps

1. Edit `.env` with your API keys
2. Run `docker-compose up -d`
3. Wait for Ollama to be healthy
4. Pull the LLM model
5. Check application logs with `docker-compose logs cyber_battle`
