#!/bin/bash

# Exit on error
set -e

# Function to check if running as root
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "This script needs root privileges for packet capture."
        echo "Please enter your password to continue:"
        # Re-run the script with sudo and preserve environment
        exec sudo -E "$0" "$@"
    fi
}

# Function to detect OS and set environment variables
setup_environment() {
    case "$(uname -s)" in
        Darwin*)    # macOS
            export SYSTEM_LOG_PATH="/var/log"
            export SYSTEM_CONFIG_PATH="/etc"
            export USER_CONFIG_PATH="/usr/local/etc"
            export APPLICATION_DATA_PATH="/Library/Application Support"
            export PRIMARY_INTERFACE="en0"
            export SECONDARY_INTERFACE="en1"
            ;;
        Linux*)     # Linux
            export SYSTEM_LOG_PATH="/var/log"
            export SYSTEM_CONFIG_PATH="/etc"
            export USER_CONFIG_PATH="/etc"
            export APPLICATION_DATA_PATH="/var/lib"
            export PRIMARY_INTERFACE="eth0"
            export SECONDARY_INTERFACE="eth1"
            ;;
        MINGW*|CYGWIN*|MSYS*)  # Windows
            export SYSTEM_LOG_PATH="C:/Windows/Logs"
            export SYSTEM_CONFIG_PATH="C:/Windows/System32/config"
            export USER_CONFIG_PATH="C:/Users/$USER/AppData/Local"
            export APPLICATION_DATA_PATH="C:/ProgramData"
            export PRIMARY_INTERFACE="Ethernet"
            export SECONDARY_INTERFACE="Wi-Fi"
            ;;
        *)
            echo "Unsupported operating system"
            exit 1
            ;;
    esac
}

# Function to check if Homebrew is installed
check_homebrew() {
    if ! command -v brew &> /dev/null; then
        echo "Homebrew is not installed. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
}

# Function to install package with Homebrew
install_with_brew() {
    local package=$1
    if ! brew list $package &>/dev/null; then
        echo "Installing $package..."
        HOMEBREW_NO_AUTO_UPDATE=1 brew install --no-quarantine $package
    fi
}

# Function to check if a port is in use
check_port() {
    if lsof -i :$1 > /dev/null 2>&1; then
        echo "Port $1 is in use. Checking if it's Redis..."
        if pgrep -f "redis-server.*:$1" > /dev/null; then
            echo "Redis is already running on port $1. Using existing instance."
            return 0
        else
            echo "Error: Port $1 is in use by another process"
            exit 1
        fi
    fi
    return 0
}

# Function to start Redis
start_redis() {
    echo "Starting Redis..."
    if ! command -v redis-server &> /dev/null; then
        echo "Redis is not installed. Installing Redis..."
        install_with_brew redis
    fi
    
    # Check if Redis is already running
    if pgrep -f "redis-server.*:6379" > /dev/null; then
        echo "Using existing Redis instance"
        REDIS_PID=$(pgrep -f "redis-server.*:6379")
    else
        redis-server --port 6379 &
        REDIS_PID=$!
        sleep 2
    fi
}

# Function to start the backend
start_backend() {
    echo "Starting backend..."
    cd backend
    go run main.go &
    BACKEND_PID=$!
    cd ..
    sleep 2
}

# Function to start the agent
start_agent() {
    echo "Starting agent..."
    cd agent
    go run main.go &
    AGENT_PID=$!
    cd ..
}

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up..."
    kill $REDIS_PID 2>/dev/null || true
    kill $BACKEND_PID 2>/dev/null || true
    kill $AGENT_PID 2>/dev/null || true
}

# Set up cleanup on script exit
trap cleanup EXIT

# Check for root privileges
check_root

# Set up environment variables based on OS
setup_environment

# Check and install Homebrew if needed
check_homebrew

# Check if required ports are available
check_port 6379  # Redis
check_port 8080  # Backend
check_port 8081  # Agent health check

# Create config directories if they don't exist
mkdir -p agent/config backend/config

# Generate TLS certificates if they don't exist
if [ ! -f certs/tls.key ] || [ ! -f certs/tls.crt ]; then
    echo "Generating TLS certificates..."
    mkdir -p certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout certs/tls.key -out certs/tls.crt \
        -subj "/CN=localhost"
fi

# Generate encryption key if it doesn't exist
if [ ! -f .env ]; then
    echo "Generating encryption key..."
    ENCRYPTION_KEY=$(openssl rand -base64 32)
    echo "ENCRYPTION_KEY=$ENCRYPTION_KEY" > .env
fi

# Start services
start_redis
start_backend
start_agent

echo "All services are running!"
echo "Backend API: http://localhost:8080"
echo "Agent health check: http://localhost:8081/health"
echo "Press Ctrl+C to stop all services"

# Wait for user interrupt
wait 