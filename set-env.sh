#!/bin/bash

minikube config set cpus 4
minikube config set disk-size 65536
minikube config set memory 16384
minikube config set driver docker

minikube start --network-plugin=cni --cni=calico

minikube addons enable ingress
minikube addons enable ingress-dns

