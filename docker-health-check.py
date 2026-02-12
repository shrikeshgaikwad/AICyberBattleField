#!/usr/bin/env python3
# Health check script for AI Cyber Battlefield Docker environment (Python version for Windows)

import subprocess
import os
import sys
import time
from pathlib import Path

class HealthChecker:
    def __init__(self):
        self.checks_passed = 0
        self.checks_failed = 0
        self.workspace_dir = Path(__file__).parent
        os.chdir(self.workspace_dir)
    
    def print_header(self, text):
        print("\n" + "=" * 50)
        print(text)
        print("=" * 50 + "\n")
    
    def print_success(self, text):
        print(f"✓ {text}")
        self.checks_passed += 1
    
    def print_error(self, text):
        print(f"✗ {text}")
        self.checks_failed += 1
    
    def print_warning(self, text):
        print(f"⚠ {text}")
    
    def run_command(self, cmd, capture=True):
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                shell=True,
                timeout=5
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timeout"
        except Exception as e:
            return False, "", str(e)
    
    def check_docker(self):
        self.print_header("1. Checking Docker Installation")
        
        success, _, _ = self.run_command("docker --version")
        if success:
            stdout, _, _ = self.run_command("docker --version")
            self.print_success(f"Docker is installed")
        else:
            self.print_error("Docker is not installed or not running")
    
    def check_docker_compose(self):
        self.print_header("2. Checking Docker Compose")
        
        success, _, _ = self.run_command("docker-compose --version")
        if success:
            self.print_success("Docker Compose is installed")
        else:
            self.print_error("Docker Compose is not installed")
    
    def check_env_file(self):
        self.print_header("3. Checking Environment Configuration")
        
        env_file = self.workspace_dir / ".env"
        example_file = self.workspace_dir / ".env.example"
        
        if env_file.exists():
            self.print_success(".env file exists")
        else:
            if example_file.exists():
                self.print_warning(".env not found, creating from .env.example")
                try:
                    with open(example_file, 'r') as f_in:
                        content = f_in.read()
                    with open(env_file, 'w') as f_out:
                        f_out.write(content)
                    self.print_success(".env created (please review and update)")
                except Exception as e:
                    self.print_error(f"Could not create .env: {e}")
            else:
                self.print_error(".env.example not found")
    
    def check_containers(self):
        self.print_header("4. Checking Container Status")
        
        containers = [
            "ollama_service",
            "cyber_db",
            "cyber_redis",
            "cyber_battle_app"
        ]
        
        for container in containers:
            success, stdout, _ = self.run_command(
                f"docker-compose ps {container}"
            )
            
            if success and "running" in stdout.lower():
                if "healthy" in stdout.lower():
                    status = "healthy"
                else:
                    status = "running"
                self.print_success(f"{container}: {status}")
            else:
                self.print_error(f"{container}: not running or not found")
    
    def check_ports(self):
        self.print_header("5. Checking Port Availability")
        
        ports = {
            11434: "Ollama",
            5432: "PostgreSQL",
            6379: "Redis",
            8000: "App (primary)",
            8080: "App (secondary)",
            5050: "pgAdmin"
        }
        
        for port, service in ports.items():
            # Using powershell on Windows
            success, _, _ = self.run_command(
                f'powershell -Command "(Test-NetConnection -ComputerName localhost -Port {port}).TcpTestSucceeded"'
            )
            
            if success:
                self.print_success(f"Port {port} ({service}): Open")
            else:
                self.print_warning(f"Port {port} ({service}): Not reachable")
    
    def check_services(self):
        self.print_header("6. Testing Service Endpoints")
        
        # Check Ollama
        print("Testing Ollama API... ", end="")
        success, _, _ = self.run_command(
            'curl -s http://localhost:11434/api/tags > nul 2>&1'
        )
        if success:
            print("✓")
            self.checks_passed += 1
        else:
            print("✗")
            self.checks_failed += 1
        
        # Check PostgreSQL
        print("Testing PostgreSQL... ", end="")
        success, _, _ = self.run_command(
            "docker-compose exec -T postgres pg_isready -U cyber_user"
        )
        if success:
            print("✓")
            self.checks_passed += 1
        else:
            print("✗")
            self.checks_failed += 1
        
        # Check Redis
        print("Testing Redis... ", end="")
        success, _, _ = self.run_command(
            "docker-compose exec -T redis redis-cli ping"
        )
        if success:
            print("✓")
            self.checks_passed += 1
        else:
            print("✗")
            self.checks_failed += 1
    
    def show_resources(self):
        self.print_header("7. Container Resource Usage")
        
        success, stdout, _ = self.run_command(
            'docker stats --no-stream --format "table {{.Container}}\t{{.MemUsage}}\t{{.CPUPerc}}"'
        )
        if success:
            for line in stdout.split('\n'):
                if 'cyber_' in line or 'ollama_' in line:
                    print(line)
    
    def print_summary(self):
        self.print_header("Health Check Summary")
        
        total = self.checks_passed + self.checks_failed
        print(f"Passed: {self.checks_passed}/{total}")
        print(f"Failed: {self.checks_failed}/{total}")
        print()
        
        if self.checks_failed == 0:
            print("✓ All critical services appear to be healthy!")
            print("\nNext steps:")
            print("1. View logs: docker-compose logs -f")
            print("2. Access app: docker-compose exec cyber_battle bash")
            print("3. View full guide: type DOCKER_GUIDE.md")
            return 0
        else:
            print("✗ Some services need attention")
            print("\nTroubleshooting:")
            print("1. Check logs: docker-compose logs")
            print("2. Restart: docker-compose restart")
            print("3. Rebuild: docker-compose down -v && docker-compose up -d")
            return 1
    
    def run(self):
        try:
            print("\n╔════════════════════════════════════════════╗")
            print("║  AI Cyber Battlefield - Docker Health Check║")
            print("╚════════════════════════════════════════════╝\n")
            
            self.check_docker()
            self.check_docker_compose()
            self.check_env_file()
            self.check_containers()
            self.check_ports()
            self.check_services()
            self.show_resources()
            
            return self.print_summary()
        
        except KeyboardInterrupt:
            print("\n\nHealth check cancelled by user")
            return 1
        except Exception as e:
            print(f"\n\nError during health check: {e}")
            return 1

if __name__ == "__main__":
    checker = HealthChecker()
    sys.exit(checker.run())
