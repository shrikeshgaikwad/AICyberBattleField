#!/usr/bin/env python3
"""
Docker Connection Troubleshooter for Windows
Helps diagnose and fix Docker Desktop connectivity issues
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, show_output=True):
    """Run a command and return success status"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            timeout=10
        )
        if show_output and result.stdout:
            print(result.stdout)
        if result.stderr and "warning" not in result.stderr.lower():
            print(f"Error: {result.stderr}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"Command timeout: {cmd}")
        return False
    except Exception as e:
        print(f"Error running command: {e}")
        return False

def check_docker_desktop():
    """Check if Docker Desktop is running"""
    print("Checking Docker Desktop status...")
    
    # Try to get Docker without output
    success = run_command("docker info", show_output=False)
    
    if success:
        print("✓ Docker Desktop is running")
        return True
    else:
        print("✗ Docker Desktop is NOT running")
        return False

def start_docker_desktop():
    """Attempt to start Docker Desktop"""
    print("\nAttempting to start Docker Desktop...")
    
    # Try different methods
    methods = [
        ('Start-Service com.docker.service -ErrorAction SilentlyContinue', 'Service method'),
        ('"C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe"', 'Direct launch'),
        ('wsl --shutdown', 'Reset WSL (needs restart after)'),
    ]
    
    for cmd, method in methods:
        print(f"  Trying {method}...", end=" ")
        success = run_command(cmd, show_output=False)
        if success:
            print("✓")
            return True
        print("✗")
    
    return False

def verify_docker():
    """Verify Docker is working"""
    print("\nVerifying Docker functionality...")
    
    success = run_command("docker ps", show_output=False)
    
    if success:
        print("✓ Docker is functional")
        return True
    else:
        print("✗ Docker is not functional")
        return False

def check_docker_compose():
    """Check if docker-compose is available"""
    print("\nChecking Docker Compose...")
    
    success = run_command("docker-compose --version", show_output=False)
    
    if success:
        print("✓ Docker Compose is available")
        return True
    else:
        print("✗ Docker Compose is not available")
        return False

def main():
    """Main troubleshooting flow"""
    print("=" * 60)
    print("Docker Connection Troubleshooter for Windows")
    print("=" * 60)
    print()
    
    # Check if Docker is running
    if not check_docker_desktop():
        print("\n" + "!" * 60)
        print("Docker Desktop is not running!")
        print("!" * 60)
        
        print("\nWould you like me to try starting it? (Automatic attempt)")
        print()
        
        if start_docker_desktop():
            print("\nWaiting for Docker to start... (30 seconds)")
            import time
            for i in range(30):
                if check_docker_desktop():
                    print("\n✓ Docker started successfully!")
                    break
                time.sleep(1)
                print(".", end="", flush=True)
        else:
            print("\nManual action required. Please:")
            print("1. Open Docker Desktop from your Start menu")
            print("2. Wait for it to fully load (watch for 'Docker is running')")
            print("3. Run 'docker-compose up -d' again")
            print("\nYou can also check:")
            print("  - Docker Desktop Settings → General → 'Expose daemon on tcp://localhost:2375'")
            print("  - Docker Desktop Settings → Resources → WSL Integration")
            return 1
    
    # Verify Docker is working
    if not verify_docker():
        print("\n⚠ Docker exists but not responding correctly")
        print("Try restarting Docker Desktop")
        return 1
    
    # Check Docker Compose
    if not check_docker_compose():
        print("\n⚠ Docker Compose not found or not in PATH")
        print("Installing docker-compose...")
        run_command("pip install docker-compose", show_output=True)
    
    print("\n" + "=" * 60)
    print("✓ Docker environment appears ready!")
    print("=" * 60)
    print("\nYou can now run:")
    print("  docker-compose up -d")
    print("\nOr use Make commands:")
    print("  make up")
    print("  make health")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
