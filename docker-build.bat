@echo off
REM Docker build and deployment script for CyberRecon (Windows)

echo CyberRecon Docker Deployment Script
echo ======================================

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    exit /b 1
)

REM Build the Docker image
echo [INFO] Building CyberRecon Docker image...
docker build -t cyberrecon:latest .

if %errorlevel% neq 0 (
    echo [ERROR] Failed to build Docker image
    exit /b 1
)

REM Create necessary directories
echo [INFO] Creating necessary directories...
if not exist logs mkdir logs
if not exist reports mkdir reports
if not exist config mkdir config

echo.
echo Docker image built successfully!
echo.
echo Usage examples:
echo ===============
echo.
echo 1. Run basic scan:
echo    docker run --rm -v %cd%/reports:/app/reports cyberrecon:latest example.com --all
echo.
echo 2. Run with custom output:
echo    docker run --rm -v %cd%/reports:/app/reports cyberrecon:latest example.com --whois --dns --output-format html
echo.
echo 3. Run with verbose logging:
echo    docker run --rm -v %cd%/logs:/app/logs -v %cd%/reports:/app/reports cyberrecon:latest example.com --all --log-level DEBUG
echo.
echo 4. Run interactive mode:
echo    docker run --rm -it -v %cd%/reports:/app/reports cyberrecon:latest
echo.
echo 5. Using Docker Compose:
echo    docker-compose run --rm cyberrecon example.com --all
echo.
echo Note: For port scanning, you may need to add --privileged flag for advanced features
