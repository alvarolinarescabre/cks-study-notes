#!/bin/bash

# Set Parameters Configs
minikube config set cpus 4
minikube config set disk-size 50000
minikube config set memory 15617
minikube config set driver docker

# Start Cluster with CNI
minikube start --nodes 3 --network-plugin=cni

# Enable Ingress Addons
minikube addons enable ingress
minikube addons enable ingress-dns

# Install Cilium
curl -LO https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz
sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
rm cilium-linux-amd64.tar.gz
cilium install

# Install ArgoCD
kubectl create ns argocd
helm repo add argo https://argoproj.github.io/argo-helm
helm upgrade --install my-argo-cd argo/argo-cd --version 7.6.12 --values argo-values.yaml
minikube ip

