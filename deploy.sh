#!/bin/bash

# Exit on error
set -e

# Function to check if kubectl is configured
check_kubectl() {
    if ! kubectl cluster-info &>/dev/null; then
        echo "Error: kubectl is not configured or cluster is not running"
        echo "Please ensure you have a Kubernetes cluster running and kubectl is configured"
        echo "You can use Docker Desktop's Kubernetes or Minikube:"
        echo "1. For Docker Desktop: Enable Kubernetes in Docker Desktop preferences"
        echo "2. For Minikube: Run 'minikube start'"
        exit 1
    fi
}

# Function to check if Docker is running
check_docker() {
    if ! docker info &>/dev/null; then
        echo "Error: Docker is not running"
        echo "Please start Docker Desktop"
        exit 1
    fi
}

# Function to setup local registry
setup_registry() {
    echo "Setting up local registry..."
    # Remove existing registry container if it exists
    if docker ps -a | grep -q registry:2; then
        echo "Removing existing registry container..."
        docker rm -f registry
    fi
    
    echo "Creating new registry container..."
    docker run -d -p 5001:5000 --restart=always --name registry registry:2
    
    # Wait for registry to be ready
    echo "Waiting for registry to be ready..."
    sleep 5
}

echo "Checking prerequisites..."
check_docker
check_kubectl

echo "Setting up local registry..."
setup_registry

echo "Creating namespace..."
kubectl create namespace smartshield --dry-run=client -o yaml | kubectl apply -f - --validate=false

echo "Generating TLS certificates..."
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/tls.key -out certs/tls.crt \
  -subj "/CN=smartshield-backend.smartshield.svc.cluster.local"

echo "Creating secrets..."
# Generate encryption key
ENCRYPTION_KEY=$(openssl rand -base64 32)

# Create agent secrets
kubectl create secret generic agent-secrets \
  --namespace smartshield \
  --from-literal=backend-url=https://smartshield-backend.smartshield.svc.cluster.local:8080/api/v1/data \
  --from-literal=encryption-key=$ENCRYPTION_KEY \
  --dry-run=client -o yaml | kubectl apply -f - --validate=false

# Create backend secrets
kubectl create secret generic backend-secrets \
  --namespace smartshield \
  --from-literal=redis-url=redis://redis.smartshield.svc.cluster.local:6379 \
  --from-literal=elasticsearch-url=http://elasticsearch.smartshield.svc.cluster.local:9200 \
  --from-file=tls-cert=certs/tls.crt \
  --from-file=tls-key=certs/tls.key \
  --dry-run=client -o yaml | kubectl apply -f - --validate=false

echo "Preparing config files..."
# Create config directories if they don't exist
mkdir -p agent/config backend/config

# Only copy config files if they don't exist
if [ ! -f agent/config/config.yaml ]; then
    echo "Creating agent config..."
    cat > agent/config/config.yaml << 'EOF'
agent_id: ${AGENT_ID}
backend:
  url: ${BACKEND_URL}
  timeout: 10s
tls:
  insecure_skip_verify: false
security:
  enable_payload_encryption: true
  rate_limit: 100
  rate_limit_burst: 200
  encryption_key: ${ENCRYPTION_KEY}
monitoring:
  metrics_interval: 30s
  health_check_interval: 60s
  health_check_port: 8081
network:
  interface: eth0
  bpf_filter: ""
system:
  log_paths:
    - /var/log/syslog
    - /var/log/auth.log
EOF
fi

if [ ! -f backend/config/config.yaml ]; then
    echo "Creating backend config..."
    cat > backend/config/config.yaml << 'EOF'
server:
  port: 8080
  tls:
    enabled: true
    cert_path: /app/certs/tls.crt
    key_path: /app/certs/tls.key
redis:
  pool_size: 10
  min_idle_conns: 5
  max_retries: 3
elasticsearch:
  max_retries: 3
  timeout: 10s
detection:
  yara_rules_path: /app/rules
  scan_timeout: 5s
  max_concurrent_scans: 10
security:
  rate_limit: 1000
  rate_limit_burst: 2000
  max_request_size: 10485760  # 10MB
EOF
fi

echo "Building and pushing Docker images..."
# Build agent image
docker build -t localhost:5001/smartshield/agent:latest ./agent
docker push localhost:5001/smartshield/agent:latest

# Build backend image
docker build -t localhost:5001/smartshield/backend:latest ./backend
docker push localhost:5001/smartshield/backend:latest

echo "Updating Kubernetes manifests to use local registry..."
# Update image references in deployment files
sed -i '' 's|smartshield/agent:latest|localhost:5001/smartshield/agent:latest|g' agent/k8s/deployment.yaml
sed -i '' 's|smartshield/backend:latest|localhost:5001/smartshield/backend:latest|g' backend/k8s/deployment.yaml

echo "Deploying components..."
# Deploy Redis
kubectl apply -f backend/k8s/redis.yaml --validate=false

# Deploy Elasticsearch
kubectl apply -f backend/k8s/elasticsearch.yaml --validate=false

# Deploy backend
kubectl apply -f backend/k8s/configmap.yaml --validate=false
kubectl apply -f backend/k8s/network-policy.yaml --validate=false
kubectl apply -f backend/k8s/deployment.yaml --validate=false
kubectl apply -f backend/k8s/service.yaml --validate=false

# Deploy agent
kubectl apply -f agent/k8s/configmap.yaml --validate=false
kubectl apply -f agent/k8s/network-policy.yaml --validate=false
kubectl apply -f agent/k8s/deployment.yaml --validate=false

echo "Waiting for deployments to be ready..."
kubectl wait --namespace smartshield \
  --for=condition=available \
  --timeout=300s \
  deployment/redis \
  deployment/elasticsearch \
  deployment/smartshield-backend \
  deployment/smartshield-agent

echo "Deployment complete! Checking pod status..."
kubectl get pods -n smartshield

echo "Testing connectivity..."
# Test backend health
kubectl exec -n smartshield deploy/smartshield-agent -- wget -qO- --no-check-certificate https://smartshield-backend.smartshield.svc.cluster.local:8080/health

echo "System is ready for testing!" 