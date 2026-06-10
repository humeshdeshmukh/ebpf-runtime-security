#!/bin/bash
# ==============================================================================
# eBPF Runtime Security & SRE Observability - Cleanup Script
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${YELLOW}============================================================${NC}"
echo -e "${YELLOW}   🧹 CLEANING UP eBPF OBSERVABILITY PLATFORM               ${NC}"
echo -e "${YELLOW}============================================================${NC}"

# Kill local Flask process
echo -e "${BLUE}>>> Stopping local SRE Dashboard app...${NC}"
pkill -f "python dashboard-app/app.py" || true

# Delete workloads
echo -e "${BLUE}>>> Deleting Kubernetes pods and policies...${NC}"
kubectl delete pod payment-gateway compromised-pod --ignore-not-found=true || true
kubectl delete -f tetragon/policies/ --ignore-not-found=true || true
kubectl delete -f hubble-telemetry/egress_rules.yaml --ignore-not-found=true || true

# Uninstall Helm releases
echo -e "${BLUE}>>> Uninstalling Helm releases...${NC}"
helm uninstall tetragon -n kube-system || true
helm uninstall cilium -n kube-system || true

# Stop Minikube
echo -e "${BLUE}>>> Stopping Minikube...${NC}"
minikube stop || true

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  ✓ Cleanup completed successfully!                          ${NC}"
echo -e "${GREEN}============================================================${NC}"
