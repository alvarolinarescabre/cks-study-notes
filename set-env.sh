#/bin/bash

minikube config set cpus 4
minikube config set memory 8192

minikube start

minikube addons enable ingress
minikube addons enable ingress-dns

