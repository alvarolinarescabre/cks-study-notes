#!/bin/bash

# Set Parameters Configs
minikube config set cpus 4
minikube config set disk-size 50000
minikube config set memory 15617
minikube config set driver docker

# Start Cluster with CNI
minikube start --network-plugin=cni

# Enable Ingress Addons
minikube addons enable ingress
minikube addons enable ingress-dns

# Install Cilium
curl -LO https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-amd64.tar.gz
sudo tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
rm cilium-linux-amd64.tar.gz
cilium install
