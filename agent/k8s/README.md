# SmartShield Agent Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the SmartShield Agent.

## Security Features

1. **Container Security**:

   - Multi-stage build to minimize image size
   - Non-root user execution
   - Read-only root filesystem
   - Minimal capabilities (NET_ADMIN, NET_RAW)
   - Seccomp and AppArmor profiles
   - Resource limits and requests

2. **Network Security**:

   - NetworkPolicy to restrict traffic
   - TLS encryption for all communications
   - Rate limiting
   - Payload encryption

3. **Secret Management**:

   - Kubernetes Secrets for sensitive data
   - Environment variable injection
   - No hardcoded credentials

4. **Monitoring**:
   - Health checks
   - Resource monitoring
   - Log collection

## Prerequisites

- Kubernetes cluster (v1.19+)
- kubectl configured
- Access to container registry
- Helm (optional, for deployment)

## Deployment Steps

1. Create the namespace:

   ```bash
   kubectl create namespace smartshield
   ```

2. Create secrets:

   ```bash
   # Generate encryption key
   ENCRYPTION_KEY=$(openssl rand -base64 32)

   # Create secrets
   kubectl create secret generic agent-secrets \
     --namespace smartshield \
     --from-literal=backend-url=https://backend.smartshield.svc.cluster.local:8080/api/v1/data \
     --from-literal=encryption-key=$ENCRYPTION_KEY
   ```

3. Apply configurations:

   ```bash
   kubectl apply -f configmap.yaml
   kubectl apply -f network-policy.yaml
   kubectl apply -f deployment.yaml
   ```

4. Verify deployment:
   ```bash
   kubectl get pods -n smartshield
   kubectl logs -n smartshield -l app=smartshield-agent
   ```

## Security Considerations

1. **Secrets Management**:

   - Use a secrets management solution (e.g., HashiCorp Vault)
   - Rotate encryption keys regularly
   - Never commit secrets to version control

2. **Network Security**:

   - Review and adjust NetworkPolicy as needed
   - Monitor network traffic
   - Use service mesh for additional security

3. **Container Security**:

   - Regularly update base images
   - Scan images for vulnerabilities
   - Monitor container runtime

4. **Monitoring and Logging**:
   - Set up centralized logging
   - Configure alerts for security events
   - Monitor resource usage

## Troubleshooting

1. Check pod status:

   ```bash
   kubectl describe pod -n smartshield -l app=smartshield-agent
   ```

2. View logs:

   ```bash
   kubectl logs -n smartshield -l app=smartshield-agent
   ```

3. Check network connectivity:
   ```bash
   kubectl exec -n smartshield -it $(kubectl get pod -n smartshield -l app=smartshield-agent -o jsonpath='{.items[0].metadata.name}') -- wget -O- http://localhost:8081/health
   ```

## Maintenance

1. Update the agent:

   ```bash
   kubectl set image deployment/smartshield-agent agent=smartshield/agent:new-version -n smartshield
   ```

2. Scale the deployment:

   ```bash
   kubectl scale deployment smartshield-agent --replicas=2 -n smartshield
   ```

3. Monitor resources:
   ```bash
   kubectl top pods -n smartshield
   ```
