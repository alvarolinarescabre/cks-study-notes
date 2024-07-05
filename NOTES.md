<details>
<summary><h1>Killer Coda CKS</h1></summary>

<details>
<summary><h2>Config Vim + Enviroment Vars</h2></summary>

```bash
vim ~/.vimrc
set expandtab
set tabstop=2
set shiftwidth=2
set paste
```

```bash
export dr="--dry-run=client -o yaml"
export del="--wait=0 --timeout=0 --force"
```
</details>


<details>
<summary><h2>Kube-Api Server Crash</h2></summary>

```bash
journal -u kubelet
tail -f /var/log/syslog
tail -f /var/log/pods
tail -f /var/log/containers
crictl ps and crictl logs
docker ps and docker logs
```

- Find Messages:
  - "Failed while requesting a signed certificate from the control plane"
  - "connect: connection refused"
  - "couldn't parse as pod(Object 'apiVersion' is missing in"

- Check WITHOUT using /var/ directory

```bash
crictl ps <id-container>
```

- Check and Fix:

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
watch crictl ps
k get nodes
```
</details> 


<details>
<summary><h2>Kube-Api Server NodeRestriction</h2></summary>

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml add -> --enable-admission-plugins=NodeRestriction 
```

- Set label to node: 

```bash
ssh <connect-to-node-restrict>
export KUBECONFIG=/etc/kubernetes/kubelet.conf
k label nodes node-restriction.kubernetes.io/<some-key>=<some-value> 
```  
</details>


<details>
<summary><h2>AppArmor</h2></summary>

- To check status and profiles: 

```bash
apparmor_status | grep <profile-name>
```

- Enable AppArmor Profile:

```bash
apparmor_parser <path-to-profile>
apparmor_status | grep <name-of-the-apparmor-profile>
```

- To apply on Pod or Deployment AppArmor Profile add on Annotations:

```yaml
annotations:
  container.apparmor.security.beta.kubernetes.io/<pod-name>: localhost/<apparmor-profile>
```  
</details>


<details>
<summary><h2>Auditing Enable + Audit Logs</h2></summary>

- First at all, create the dir logs:

```bash
mkdir -p /etc/kubernetes/audit-logs
```

- Edit kube-apiserver.yaml

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

- Now add the follow config:

```yaml
- --audit-policy-file=/etc/kubernetes/audit-policy/policy.yaml
- --audit-log-path=/etc/kubernetes/audit-logs/audit.log
- --audit-log-maxsize=7
- --audit-log-maxbackup=2
```

- Set **volumeMounts**:

```yaml
- mountPath: /etc/kubernetes/audit-policy/policy.yaml
    name: audit-policy
    readOnly: true
- mountPath: /etc/kubernetes/audit-logs
    name: audit-logs
    readOnly: false
```

- And add **volumes**:

```yaml
- name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit-policy/policy.yaml
      type: File
  - name: audit-logs
    hostPath:
      path: /etc/kubernetes/audit-logs
      type: DirectoryOrCreate
```

- To check run:

```bash
watch -n 1 crictl ps -a
```

- To check the logs:

```bash
tail -f /etc/kubernetes/audit-logs/audit.log
```
</details>


<details>
<summary><h2>Certificate Signing Request Sign Manually and Create New Context</h2></summary>

- Create Key:

```bash
openssl genrsa -out chamo.key 2048
```

- Request CSR:

```bash
openssl req -new -key chamo.key -out chamo.csr
```

- Sign Manually the CSR with CA to create CSR:

```bash
openssl x509 -req -in chamo.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out chamo.crt -days 365
```

- Create Context

```bash
k config set-credentials admin@chamo.io --client-key=chamo.key --client-certificate=chamo.crt
k config set-context admin@chamo.io --cluster=kubernetes --user=admin@chamo.io
k config get-contexts
k config use-context admin@chamo.io
```

**NOTES**: 

- Not working because it's not have **ClusterRole** or **Role** asigned.
- In case to request **login** and **password**, forgotten pass the `--client-certificate` on `set-credentials`.
</details>


<details>
<summary><h2>In case to used the API</h2></summary>

- First create the BASE64 code certificate:

```bash
cat chamo.csr | base64 -w 0
```

- Now create a template with this contents:

```yaml
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: admin@chamo.io -> This is the User to asigned the CSR
spec:
  request: LS0tLS1CRUdJTiBD... -> This is the Base64 convert certificate
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
```

- To approved the CSR:

```bash
k -f csr.yaml create
k get csr # -> Here show the CSR Pending
k certificate approve admin@chamo.io
k get csr # -> Here show the CSR Approved
k get csr admin@chamo.io -ojsonpath="{.status.certificate}"  | base64 -d > chamo.crt
```

- Create Context

```bash
k config set-credentials admin@chamo.io --client-key=chamo.key --client-certificate=chamo.crt
k config set-context admin@chamo.io --cluster=kubernetes --user=admin@chamo.io
k config get-contexts
k config use-context admin@chamo.io
```

**NOTES**: 

- Not working because it's not have **ClusterRole** or **Role** asigned.
- In case to request **login** and **password**, forgotten pass the `--client-certificate` on `set-credentials`.
</details>  


<details>
<summary><h2>Self-Signed Certificate + Kubernetes Context</h2></summary>

- Create the Key

```bash
openssl genrsa -out chamo.key 2048
```

- Create CSR

```bash
openssl req -new -key chamo.key -out chamo.csr
```

- Create the Certificate

```bash
openssl x509 -req -signkey chamo.key -in chamo.csr -out chamo.crt
```

- Create Kubernetes Context

```bash
k config set-credentials chamo@chamo.io --client-key chamo.key --client-certificate chamo.crt
k config set-context chamo@chamo.io --cluster=kubernetes --user=chamo@chamo.io
k config get-contexts
k config use-context chamo@chamo.io
```
</details>


<details>
<summary><h2>CIS Brenchmarks fix ControlPlane</h2></summary>

- To run kube-bench specific hosts:
```bash
kube-bench run --targets <node-name>
```

- To check a specific fix:
```bash
kube-brench run --targets <node-name> --check <fix-name>
```
</details>


<details>
<summary><h2>Container Hardening</h2></summary>

```dockerfile
FROM ubuntu:20.04 # <- Set Version
RUN apt-get update && apt-get -y install curl # <- Remove layer cache
ENV URL https://google.com/this-will-fail?secret-token=
RUN rm -rf /usr/bin/bash # <- Remove Bash Access
CMD ["sh", "-c", "curl --head $URL=$TOKEN"] # <- Uses Env Var Instead Hardcode
```
</details>

<details>
<summary><h2>Container Image Footprint User</h2></summary>

- Add on Dockerfile USER <username> to run process with this user and not user root
</details>

<details>
<summary><h2>Container Namespaces Docker</h2></summary>

- Run first container:

```bash
docker run --name app1 -d nginx:alpine sleep infinity
```

- Run second container with shared PID

```bash
docker run --name app2 --pid=container:app1 -d nginx:alpine sleep infinity
```

- Check process ob both containers

```bash
docker exec app1 ps aux
docker exec app2 ps aux
```

- See same proceess on both containers because shared the same namespaces
</details>


<details>
<summary><h2>ImagePolicyWebhook Setup</h2></summary>

- Set config file, allowTTL and defaultAllow to apply policy: vim /etc/kubernetes/policywebhook/admission_config.json 

- `admission_config.json`

```json
{
   "apiVersion": "apiserver.config.k8s.io/v1",
   "kind": "AdmissionConfiguration",
   "plugins": [
       {
           "name": "ImagePolicyWebhook",
           "configuration": {
               "imagePolicy": {
                   "kubeConfigFile": "/etc/kubernetes/policywebhook/kubeconf",
                   "allowTTL": 100,
                   "denyTTL": 50,
                   "retryBackoff": 500,
                   "defaultAllow": false
               }
           }
       }
   ]
}
```

- Change this one: vim /etc/kubernetes/policywebhook/kubeconf # iAdd <- server: https://localhost:1234 

- Set ImagePolicy WebHook: vim /etc/kubernetes/manifests/kube-apiserver.yaml # Add <- - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/policywebhook/admission_config.json
```

- To test:

```bash
k run pod --image=nginx
```
</details>


<details>
<summary><h2>Image Use Digest</h2></summary>

- To run a Pod with image digest run this:

```bash
k run nginx-web --image=nginx@sha256:eb05700fe7baa6890b74278e39b66b2ed1326831f9ec3ed4bdc6361a4ac2f333
```

- To change in deployment:

```bash
k edit deploy chamo-deploy # <- Change -> image: httpd@sha256:c7b8040505e2e63eafc82d37148b687ff488bf6d25fc24c8bf01d71f5b457531
```
</details>


<details>
<summary><h2>Image Vulnerability Scanning Trivy</h2></summary>

- To find image on pods in a particular ns:

```bash
k -n applications get pod -oyaml | grep image:
```

- To scan and find vulnerability:

```bash
trivy image nginx:1.19.1-alpine-perl | grep CVE-2021-28831
trivy image nginx:1.19.1-alpine-perl | grep CVE-2016-9841
```
</details>


<details>
<summary><h2>Immutability Readonly Filesystem</h2></summary>

- Create a container with root filesystem read-only

```bash
k run pod-ro --image=busybox:1.32.0 -oyaml --dry-run=client --command -- sh -c 'sleep 1d' > pod.yaml 
```

- The pod.yaml

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: pod-ro
  name: pod-ro
  namespace: sun
spec:
  containers:
  - command:
    - sh
    - -c
    - sleep 1d
    image: busybox:1.32.0
    name: pod-ro
    securityContext: # <- Add this
      readOnlyRootFilesystem: true # <- Add this
  dnsPolicy: ClusterFirst
  restartPolicy: Always
```
</details>


<details>
<summary><h2>Ingress Secure</h2></summary>

- Create Self-Signed Certificate

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout chamo.key -out chamo.crt -subj "/CN=www.chamo.io/O=chamo.io"
```

- To check certificate:

```bash
openssl x509 -text -noout -in chamo.crt
```

- Create TLS Secret

```bash
kubectl create secret tls chamo-tls --key chamo.key --cert chamo.crt
```

- To create a Ingress Secure

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-secure
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "false" # <- Add this
    nginx.ingress.kubernetes.io/use-regex: "true" # <- Add this
    nginx.ingress.kubernetes.io/rewrite-target: / # Add this
spec:
  ingressClassName: nginx
  tls:                            # <- Add this
  - hosts:                        # <- Add this
    - www.chamo.io                # <- Add this
    secretName: chamo-tls         # <- Add this
  rules:
  - host: "www.chamo.io"
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web
            port:
              number: 80
```
</details>


<details>
<summary><h2>NetworkPolicy Create Default Deny</h2></summary>

- Create NetPol

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-out
  namespace: app
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 53
      protocol: TCP
    - port: 53
      protocol: UDP
```

- Apply: `k apply -f netpol.yaml`

- To check:

```bash
k -n <namespace> exec <pod> -- curl <another-pod>
k -n app exec <pod> -- nslookup <another-pod>
```
</details>


<details>
<summary><h2>NetworkPolicy Metadata Protection</h2></summary>

- Create Netpol:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metadata-server
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: chamo
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
          - 169.254.169.254/32
```

- To apply: `k apply -f netpol.yaml`

- To check: `k exec <pod> -- nc -v 169.254.169.254 80`
</details>


<details>
<summary><h2>NetworkPolicy Namespace Selector</h2></summary>

- Create Netpol on first namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
  namespace: space1
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
     - namespaceSelector:
        matchLabels:
         kubernetes.io/metadata.name: space2
  - ports:
    - port: 53
      protocol: TCP
    - port: 53
      protocol: UDP
``` 

- Create Netpol on second namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: np
  namespace: space2
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
   - from:
     - namespaceSelector:
        matchLabels:
         kubernetes.io/metadata.name: space1
```

- Apply both:

```bash
k apply -f netpol-1.yaml
k apply -f netpol-2.yaml
```

- To check:

```bash
k -n <first-namespace> exec <pod> -- nslookup <service>.default.svc.cluster.local
k -n <second-namespace> exec <pod> -- nslookup <service>.default.svc.cluster.local
```
</details>


<details>
<summary><h2>Privilege Escalation Containers</h2></summary>

- Create Deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: logger
  name: logger
  namespace: default
spec:
  progressDeadlineSeconds: 600
  replicas: 3
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app: logger
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: logger
    spec:
      containers:
      - command:
        - sh
        - -c
        - while true; do cat /proc/1/status | grep NoNewPrivs; sleep 1; done
        image: bash:5.0.18-alpine3.14
        imagePullPolicy: IfNotPresent
        name: httpd
        securityContext: # <- Add this
            allowPrivilegeEscalation: false # <- Add this
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
      dnsPolicy: ClusterFirst
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      terminationGracePeriodSeconds: 0
```

- Apply the template: `k apply -f deploy.yaml`
</details>


<details>
<summary><h2>Privileged Containers</h2></summary>

- Create pod "chamo" with `privileged: true`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: prime
  name: prime
  namespace: default
spec:
  containers:
  - image: nginx:alpine
    imagePullPolicy: IfNotPresent
    name: prime
    securityContext:
      privileged: true
  dnsPolicy: ClusterFirst
  restartPolicy: Always
```

- Check install `iptables`:

```bash
k exec prime -- apk add iptables
k exec prime -- iptables -L
```
</details>


<details>
<summary><h2>RBAC ServiceAccount Permissions</h2></summary>

- First create two namespaces:

```bash
k create ns ns1
k create ns ns2
```

- Now create a ServiceAccount called "chamo" on both Namespaces:

```bash
k -n ns1 create sa chamo
k -n ns2 create sa chamo
```

- Allowed these ServiceAccounts shloud allowed to view almost everythings in the whole cluster:

```bash
k get clusterrole view
k create clusterrolebinding pipeline-view --clusterrole view --serviceaccount ns1:pipeline --serviceaccount ns2:pipeline
```

- These ServcieAccount be allowed to create and delete Deployments in their Namespaces:

```bash
k create clusterrole -h
k create clusterrole chamo-deployment-manager --verb create,delete --resource deployments
k -n ns1 create rolebinding chamo-deployment-manager --clusterrole chamo-deployment-manager --serviceaccount ns1:chamo
k -n ns2 create rolebinding chamo-deployment-manager --clusterrole chamo-deployment-manager --serviceaccount ns2:chamo
```

- Check this ones:

```bash
k auth can-i delete deployments --as system:serviceaccount:ns1:chamo -n ns1 # YES
k auth can-i create deployments --as system:serviceaccount:ns1:chamo -n ns1 # YES
k auth can-i update deployments --as system:serviceaccount:ns1:chamo -n ns1 # NO
k auth can-i update deployments --as system:serviceaccount:ns1:chamo -n default # NO

# namespace ns2 deployment manager
k auth can-i delete deployments --as system:serviceaccount:ns2:chamo -n ns2 # YES
k auth can-i create deployments --as system:serviceaccount:ns2:chamo -n ns2 # YES
k auth can-i update deployments --as system:serviceaccount:ns2:chamo -n ns2 # NO
k auth can-i update deployments --as system:serviceaccount:ns2:chamo -n default # NO

# cluster wide view role
k auth can-i list deployments --as system:serviceaccount:ns1:chamo -n ns1 # YES
k auth can-i list deployments --as system:serviceaccount:ns1:chamo -A # YES
k auth can-i list pods --as system:serviceaccount:ns1:chamo -A # YES
k auth can-i list pods --as system:serviceaccount:ns2:chamo -A # YES
k auth can-i list secrets --as system:serviceaccount:ns2:chamo -A # NO
```
</details>


<details>
<summary><h2>RBAC User Permissions</h2></summary>

- Create a User `chamo`to do this:
  - `create` and `delete` Pods
  - `view` all namespaces but not in `kube-system`
  - Retrive Secrets un Namespace `applications`


```bash
# Create Namespaces
k create ns applications

# Create and Delete Pods
k -n applications create role chamo --verb create,delete --resource pods,deployments,sts
k -n applications create rolebinding chamo --role chamo --user chamo

# view Permission in all Namespaces but not kube-system
k get ns
k -n applications create rolebinding chamo-view --clusterrole view --user chamo
k -n default create rolebinding chamo-view --clusterrole view --user chamo
k -n kube-node-lease create rolebinding chamo-view --clusterrole view --user chamo
k -n kube-public create rolebinding chamo-view --clusterrole view --user chamo

# Just list Secret, no content
k -n applications create role list-secrets --verb list --resource secrets
```
</details>


<details>
<summary><h2>Sandbox gVisor</h2></summary>

- Install gVisor --> gvisor-install.sh:

```bash
#!/usr/bin/env bash
# IF THIS FAILS then you can try to change the URL= further down from specific to the latest release
# https://gvisor.dev/docs/user_guide/install


# gvisor
sudo apt-get update && \
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common


# install from web
(
  set -e
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/20230925/${ARCH}
  # URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH} # TRY THIS URL INSTEAD IF THE SCRIPT DOESNT WORK FOR YOU
  wget ${URL}/runsc ${URL}/runsc.sha512 \
    ${URL}/containerd-shim-runsc-v1 ${URL}/containerd-shim-runsc-v1.sha512
  sha512sum -c runsc.sha512 \
    -c containerd-shim-runsc-v1.sha512
  rm -f *.sha512
  chmod a+rx runsc containerd-shim-runsc-v1
  sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin
)


# containerd enable runsc
cat > /etc/containerd/config.toml <<EOF
disabled_plugins = []
imports = []
oom_score = 0
plugin_dir = ""
required_plugins = []
root = "/var/lib/containerd"
state = "/run/containerd"
version = 2
[plugins]
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
    runtime_type = "io.containerd.runsc.v1"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
      base_runtime_spec = ""
      container_annotations = []
      pod_annotations = []
      privileged_without_host_devices = false
      runtime_engine = ""
      runtime_root = ""
      runtime_type = "io.containerd.runc.v2"
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
        BinaryName = ""
        CriuImagePath = ""
        CriuPath = ""
        CriuWorkPath = ""
        IoGid = 0
        IoUid = 0
        NoNewKeyring = false
        NoPivotRoot = false
        Root = ""
        ShimCgroup = ""
        SystemdCgroup = true
EOF
```

- Create a **RuntimeClass**:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

- Create a **Pod** with gVisor RuntimeClass:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: <pod-name>
spec:
  runtimeClassName: gvisor
  containers:
    - image: nginx:1.21.5-alpine
      name: sec
  dnsPolicy: ClusterFirst
  restartPolicy: Always
```

- Verify:

```bash
k exec <pod-name> -- dmesg | grep -i gvisor
```
</details>


<details>
<summary><h2>Secret ETCD Encryption</h2></summary>

- Generate EncryptionConfiguration:

```bash
mkdir -p /etc/kubernetes/etcd
echo -n this-is-very-sec | base64
```

- ec.yaml:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aesgcm:
        keys:
        - name: key1
          secret: dGhpcy1pcy12ZXJ5LXNlYw==
    - identity: {}
```

- Add a new volume and volumeMount in `/etc/kubernetes/manifests/kube-apiserver.yaml`, so that the container can access the file:

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

- Add argument: `--encryption-provider-config=/etc/kubernetes/etcd/ec.yaml`

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
...
    - --encryption-provider-config=/etc/kubernetes/etcd/ec.yaml
...
    volumeMounts:
    - mountPath: /etc/kubernetes/etcd
      name: etcd
      readOnly: true
...
  hostNetwork: true
  priorityClassName: system-cluster-critical
  volumes:
  - hostPath:
      path: /etc/kubernetes/etcd
      type: DirectoryOrCreate
    name: etcd
```

- Verify:

```bash
watch crictl ps
```

- Encrypt all existing Secrets:

```bash
kubectl -n <secret-name> get secrets -o json | kubectl replace -f -
```

- Verify:

```bash
ETCDCTL_API=3 etcdctl --cert /etc/kubernetes/pki/apiserver-etcd-client.crt --key /etc/kubernetes/pki/apiserver-etcd-client.key --cacert /etc/kubernetes/pki/etcd/ca.crt get /registry/secrets/<namespaces>/<secret-name>
```
</details>


<details>
<summary><h2>Secret Access in Pods</h2></summary>

- First create a **Secret**:

```bash
kubectl create secret generic holy --from-literal creditcard=1111222233334444
```

- Now create a **Secret** from file:

```yaml
apiVersion: v1
data:
  hosts: MTI3LjAuMC4xCWxvY2FsaG9zdAoxMjcuMC4xLjEJaG9zdDAxCgojIFRoZSBmb2xsb3dpbmcgbGluZXMgYXJlIGRlc2lyYWJsZSBmb3IgSVB2NiBjYXBhYmxlIGhvc3RzCjo6MSAgICAgbG9jYWxob3N0IGlwNi1sb2NhbGhvc3QgaXA2LWxvb3BiYWNrCmZmMDI6OjEgaXA2LWFsbG5vZGVzCmZmMDI6OjIgaXA2LWFsbHJvdXRlcnMKMTI3LjAuMC4xIGhvc3QwMQoxMjcuMC4wLjEgaG9zdDAxCjEyNy4wLjAuMSBob3N0MDEKMTI3LjAuMC4xIGNvbnRyb2xwbGFuZQoxNzIuMTcuMC4zNSBub2RlMDEKMTcyLjE3LjAuMjMgY29udHJvbHBsYW5lCg==
kind: Secret
metadata:
  name: diver
```

- Apply **Secret** file:

```bash
k apply -f <secret-file-name>
```

- Create a **Pod** with **Secret** Env Vars and Volume:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec:
  volumes:
  - name: diver
    secret:
      secretName: diver
  containers:
  - image: nginx
    name: pod1
    volumeMounts:
      - name: diver
        mountPath: /etc/diver
    env:
      - name: HOLY
        valueFrom:
          secretKeyRef:
            name: holy
            key: creditcard
```

- Apply **Pod**:

```bash
k apply -f <pod-filename>
```

- Verify:

```bash
kubectl exec pod1 -- env | grep "HOLY=1111222233334444"
kubectl exec pod1 -- cat /etc/diver/hosts
```
</details>


<details>
<summary><h2>Secret Read and Decode</h2></summary>

- To decode **Secret**:

```bash
kubectl -n <secret-name> get secret s1 -ojsonpath="{.data.<data-name>}" | base64 -d
```
</details>


<details>
<summary><h2>Secret ServiceAccount Pod</h2></summary>

- Create a **Namespace**:

```bash
k create ns ns-secure
```

- Create a **ServiceAccount**:

```bash
k -n ns-secure create sa secret-manager
```

- Create a **Secret** a literal:

```bash
k -n ns-secure create secret generic sec-a1 --from-literal user=admin
```

- Create a **Secret** from file:

```bash
k -n ns-secure create secret generic sec-a2 --from-file index=/etc/hosts
```

- Create a **Pod** template and edit:

```bash
k -n ns-secure run secret-manager --image=httpd:alpine -oyaml --dry-run=client > pod.yaml
vim pod.yaml
```

- Add **Secret** Env Var and Volume:

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: secret-manager
  name: secret-manager
  namespace: ns-secure
spec:
  volumes:
    - name: sec-a2
      secret:
        secretName: sec-a2
  serviceAccountName: secret-manager
  containers:
    - image: httpd:alpine
      name: secret-manager
      volumeMounts:
        - name: sec-a2
          mountPath: /etc/sec-a2
          readOnly: true
      env:
        - name: SEC_A1
          valueFrom:
            secretKeyRef:
              name: sec-a1
              key: user
  dnsPolicy: ClusterFirst
  restartPolicy: Always
```

- Apply template:

```bash 
k apply -f pod.yaml
```
</details>


<details>
<summary><h2>ServiceAccount Token Mounting</h2></summary>

- Create a **Pod** without **ServiceAccount** token mounting:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-one
  namespace: one
spec:
  serviceAccountName: custom
  automountServiceAccountToken: false # <- Add this
  containers:
  - name: webserver
    image: nginx:1.19.6-alpine
    ports:
    - containerPort: 80
```

- Apply template:

```bash
k apply -f <template-name>
```

- Verify:

```bash
kubectl -n one exec -it pod-one -- mount | grep serviceaccount
kubectl -n one exec -it pod-one -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

- Prevent to `default` **ServiceAccount** token mounting:

```bash
apiVersion: v1
kind: ServiceAccount
automountServiceAccountToken: false # <- Add this
metadata:
  name: default
  namespace: two
```

- Verify:

```bash
kubectl -n two exec -it pod-two -- mount | grep serviceaccount
kubectl -n two exec -it pod-two -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```
</details>


<details>
<summary><h2>Static Manual Analysis Docker</h2></summary>

- Correct way to do **Dockerfile** with **Multi Stages**:

```dockerfile
FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y golang-go=2:1.13~1ubuntu2
COPY app.go .
RUN CGO_ENABLED=0 go build app.go

FROM alpine:3.12.0
RUN addgroup -S appgroup && adduser -S appuser -G appgroup -h /home/appuser
COPY --from=0 /app /home/appuser/
USER appuser
CMD ["/home/appuser/app"]
```

- Correct way to uses **Secret Token** on **Dockerfile** with Env Var:

```dockerfile
FROM ubuntu
COPY my.cnf /etc/mysql/conf.d/my.cnf
COPY mysqld_charset.cnf /etc/mysql/conf.d/mysqld_charset.cnf
RUN apt-get update && \
    apt-get -yq install mysql-server-5.6 &&
COPY import_sql.sh /import_sql.sh
COPY run.sh /run.sh
RUN /etc/register.sh $SECRET_TOKEN # <- This way
EXPOSE 3306
CMD ["/run.sh"]
```
</details>


<details>
<summary><h2>Static Manual Analysis K8s</h2></summary>


- Create a **Pod** template with readonly root filesystem:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod
spec:
  containers:
  - name: main
    image: alpine
    command: ["/bin/sleep", "999999"]
    securityContext: # <- Add this
      readOnlyRootFilesystem: true # <- Add this
  dnsPolicy: ClusterFirst
  restartPolicy: Always
```


- Correct way on **Deployment** to prevent privilege escalation:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      securityContext: # <- Add this
        runAsNonRoot: true # <- Add this
        runAsUser: 10001 # <- Add this
      containers:
      - name: nginx
        image: nginx:1.21.6
        ports:
        - containerPort: 80
```

- Correct way on **StatefulSet** to prevent privileged:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mysql-set
spec:
  selector:
    matchLabels:
      app: mysql
  serviceName: "mysql"
  replicas: 3
  template:
    metadata:
      labels:
        app: mysql
    spec:
      terminationGracePeriodSeconds: 10
      containers:
      - name: mysql
        image: mysql:5.7
        ports:
        - containerPort: 3306
        volumeMounts:
        - name: mysql-store
          mountPath: /var/lib/mysql
        securityContext: # <- Add this
          privileged: false # <- Add this
        env:
          - name: MYSQL_ROOT_PASSWORD
            valueFrom:
              secretKeyRef:
                name: mysql-password
                key: MYSQL_ROOT_PASSWORD
        readinessProbe:
          tcpSocket:
            port: 3306
          initialDelaySeconds: 10
          periodSeconds: 5
        startupProbe:
          tcpSocket:
            port: 3306
          initialDelaySeconds: 10
          periodSeconds: 5
        livenessProbe:
          tcpSocket:
            port: 3306
          initialDelaySeconds: 10
          periodSeconds: 5
  volumeClaimTemplates:
  - metadata:
      name: mysql-store
    spec:
      accessModes: ["ReadWriteOnce"]
      storageClassName: "linode-block-storage-retain"
      resources:
        requests:
          storage: 5Gi
```

<details>
<summary><h2>Syscall Activity Strace</h2></summary>

- Do a **SysCalls** to `kube-apiserver`:

```bash
ps aux | grep kube-apiserver
strace -p <pid> -f -cw
```
</details>


<details>
<summary><h2>System Hardening Close Open Ports</h2></summary>

- Install `netstat`:

```bash
apt install net-tools
```

- Check the open TCP port:

```bash
netstat -tulpan | grep 1234
```

- Check the files open by process of TCP port:

```bash
lsof -i :1234
```

- Check the file of daemon execute:

```bash
ls -l /proc/<pid>/exe
```

- Kill process:

```bash
kill -9 <pid>
```

- Remove binary or script of malicious app:

```bash
rm -rf <path-to-bin-or-script>
```
</details>


<details>
<summary><h2>System Hardening Manage Packages</h2></summary>

- Run `kube-bench` like **Job**:

```bash
apt show kube-bench
apt remove kube-bench
```

- Check files open by daemon:

```bash
lsof -i :<tcp-port>
```

- Run `kube-bench` like **Job**:

```bash
# For Master Node
k apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-master.yaml

# For Worker Node
k apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-node.yaml
```
</details>


<details>
<summary><h2>Verify Platform Binaries</h2></summary>

- Download and untar binary:

```bash
VERSION=$(kubelet --version | cut -d ' ' -f2)
wget https://dl.k8s.io/$VERSION/kubernetes-server-linux-amd64.tar.gz
tar xzf kubernetes-server-linux-amd64.tar.gz
```

- Compare binary hashes:

```bash
whereis kubelet
sha512sum /usr/bin/kubelet
sha512sum kubernetes/server/bin/kubelet
```
</details>
</details>
</details>


<details>
	<summary><h1>Killer Shell Exam Simulator</h1></summary>

<details>
<summary><h2>Question No. 1</h2></summary>
</details>
</details>


<details>
	<summary><h1>CKS Book Scenarios</h1></summary>

<details>
<summary><h2>Problem Network Policy - Part 1</h2></summary>

- Create a **Namespace** named `dev`:

```bash
k create ns dev
```

- Create a **Pod** `demo-1` on **Namespace** `default`:

```bash
k run demo-1 --image=nginx
```

- Create a **Pod** `demo-2` on **Namespace** `dev`:

```bash
k run demo-1 --image=nginx -n dev
```

- Create a **Network Policy** to `deny egress`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress
  namespace: dev
spec:
  podSelector: {}
  policyTypes:
  - Egress
```

- Verify:

```bash
k exec -it demo-1 -- curl <pod-ip>
k exec -it demo-2 -n dev -- curl <pod-ip>
```
</details>


<details>
<summary><h2>Problem Network Policy - Part 2</h2></summary>

- Create a **Namespace** named `red`:

```bash
k create ns red
```

- Create a **Pod** `demo-1` on **Namespace** `default`:

```bash
k run demo-1 --image=nginx
```

- Create a **Pod** `demo-2` on **Namespace** `red`:

```bash
k run demo-2 --image=nginx -n red
```

- Create a **Pod** `demo-3` on **Namespace** `red` with label `demo:test`:

```bash
k run demo-3 --image=nginx -n red -l demo=test
```

- Create a **Network Policy** to allow only by label `demo:test`:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-from-ns-default
  namespace: default
spec:
  podSelector:
    matchLabels:
      run: demo-1
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: red          
      podSelector:
        matchLabels:
          demo: test
```

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-from-ns-red
  namespace: red
spec:
  podSelector:
    matchLabels:
      demo: test
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: default
      podSelector:
        matchLabels:
          run: demo-1
```

- Verify:

```bash
k exec -it demo-1 -- curl <pod-ip-demo-3> # OK
k exec -it demo-1 -- curl <pod-ip-demo-2> # KO
k exec -it demo-2 -n red -- curl <pod-ip-demo-3> # KO
```
</details>


<details>
<summary><h2>Problem 3 - AppArmor Profile</h2></summary>

- Create a **AppArmor Profile** on Master and Each Node

```bash
NODES=($(kubectl get nodes -o name))

for NODE in ${NODES[*]}; do ssh $NODE 'sudo apparmor_parser -q <<EOF
#include <tunables/global>

profile k8s-apparmor-example-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>

  file,

  # Deny all file writes.
  deny /** w,
}
EOF'
done
```

- Create a **Pod** with **AppArmor Profile**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: deny
spec:
  securityContext:
    appArmorProfile:
      type: Localhost
      localhostProfile: deny_write
  containers:
  - name: deny
    image: busybox
    command: [ "sh", "-c", "echo 'Hello AppArmor!' && sleep 1h" ]
```

- Verify

```bash
k exec deny -- cat /proc/1/attr/current # Enforce
k exec deny -- touch /tmp/chamo # <- Denied
```
</details>


<details>
<summary><h2>Problem 4 - RBAC</h2></summary>

- Create a **Namespace** named `demo`:

```bash
k create ns demo
```

- Create a **ServiceAccount** named `sam`on **Namespace** `demo`:

```bash
k create sa sam -n demo
```

- Create **ClusterRole**:

```bash 
k create clusterrole delete-deployments --verb=get,list,watch,delete --resource=deployments
k create clusterrole readonly-secrets --verb=list --resource=secrets
```

- Create a **RoleBinding**:

```bash
k create rolebinding delete-deployments --serviceaccount=demo:sam -n demo --clusterrole=delete-deployments
k create rolebinding readonly-secrets --serviceaccount=demo:sam -n demo --clusterrole=readonly-secrets
```

- Verify:

```bash
k auth can-i create deployments --as system:serviceaccount:demo:sam -n demo # KO
k auth can-i delete deployments --as system:serviceaccount:demo:sam -n demo # OK
k auth can-i list secrets --as system:serviceaccount:demo:sam -n demo # OK
k auth can-i create secrets --as system:serviceaccount:demo:sam -n demo # KO
```
</details>


<details>
<summary><h2>Problem 5 - Image Scanning</h2></summary>

- Install **Trivy**:

```bash
sudo -i
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh |sh -s -- -b /usr/local/bin
```

- Create three **Pod** like this:

```bash
k run p1 --image=nginx
k run p2 --image=httpd
k run p3 --image=alpine -- sleep infinity
```

- Get list images:

```bash
k get pods -o=jsonpath='{range.items[*]}{"\n"}{.metadata.name}{":\t"}{range.spec.containers[*]}{.image}{", "}{end}{end}' |sort
```


- Scan images with **Trivy**:

```bash
trivy image --severity HIGH,CRITICAL nginx
trivy image --severity HIGH,CRITICAL httpd
trivy image --severity HIGH,CRITICAL alpine
```

- Create a report on file:

```bash
echo p1 $'\n'p2 > /opt/badimages.txt
```
</details>


<details>
<summary><h2>Problem 6  - Audit Policy</h2></summary>

- Create a **Audit Policy** file on `/etc/kubernetes/audit/policy.yaml`:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"
rules:
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["deployments"]

  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods"]
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/log", "pods/status"]

  - level: None
    resources:
    - group: ""
      resources: ["configmaps"]
      resourceNames: ["controller-leader"]

  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: ""
      resources: ["endpoints", "services"]

  - level: None
    userGroups: ["system:authenticated"]
    nonResourceURLs:
    - "/api*" 
    - "/version"

  - level: Request
    resources:
    - group: ""
      resources: ["configmaps"]
    namespaces: ["kube-system"]

  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets", "configmaps"]

  - level: Request
    resources:
    - group: ""
    - group: "extensions"

  - level: Metadata
    omitStages:
      - "RequestReceived"
```

- Edit `/etc/kubernetes/manifests/kube-apiserver.yaml`:

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml
```

- Add this ones:

```yaml
spec:
containers:
  - command:
    - kube-apiserver
    - --audit-policy-file=/etc/kubernetes/audit/policy.yaml
    - --audit-log-path=/etc/kubernetes/audit/logs/audit.log
    - --audit-log-maxsize=3
    - --audit-log-maxbackup=2

...

volumeMounts:
  - mountPath: /etc/kubernetes/audit/policy.yaml
    name: audit
    readOnly: true
  - mountPath: /etc/kubernetes/audit/logs/audit.log
    name: audit-log
    readOnly: false
volumes:
  - name: audit-log
    hostPath:
      path: /etc/kubernetes/audit/logs/audit.log
      type: FileOrCreate
  - name: audit
    hostPath:
      path: /etc/kubernetes/audit/policy.yaml
      type: File
```
</details>


<details>
<summary><h2>Problem 7 - Kubernetes Upgrade</h2></summary>

- Go [here](https://killercoda.com/killer-shell-cka/scenario/cluster-upgrade).

- See possible versions:

```bash
kubeadm upgrade plan
```

- Show available versions:

```bash
apt-cache show kubeadm
```

- Upgrade `kubeadm`:

```bash
apt-get install kubeadm=1.30.1-1.1
```

- Upgrade cluster

```bash
kubeadm upgrade apply v1.30.1
```

- Upgrade `kubectl` and `kubelet`:

```bash
apt-get install kubectl=1.30.1-1.1 kubelet=1.30.1-1.1
```

- Restart `kubelet`:

```bash
service kubelet restart
```

- Verify:

```bash
k get nodes
```
</details>


<details>
<summary><h2>Problem 8 - CIS Benchmark</h2></summary>

- Got [here](https://killercoda.com/killer-shell-cks/scenario/cis-benchmarks-kube-bench-fix-controlplane).

- Run `kube-bench`:

```bash
kube-bench run --targets master
```

- Check specific issue:

```bash
kube-bench run --targets master --check 1.2.20
```

- To fix:

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml 

# Add this one
...
containers:
  - command:
    - kube-apiserver
    - --profiling=false
...
```

- Verify:

```bash
watch -n 1 crictl ps
```
</details>


<details>
<summary><h2>Problem 9 - Container Runtimes</h2></summary>

- Go [here](https://killercoda.com/killer-shell-cks/scenario/sandbox-gvisor).

- Install **gVisor** on node host:

```bash
scp gvisor-install.sh node01:/root
ssh node01 sh gvisor-install.sh
ssh node01 service kubelet status
```

- Create a **RuntimeClass**:

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
```

- Create a **Pod** with **gVisor**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: sec
spec:
  runtimeClassName: gvisor
  containers:
    - image: nginx:1.21.5-alpine
      name: sec
  dnsPolicy: ClusterFirst
  restartPolicy: Always
```

- Verify:

```bash
k exec sec -- dmesg | grep -i gvisor
```
</details>


<details>
<summary><h2>Problem 10 - Falco</h2></summary>

- Go [here](https://killercoda.com/killer-shell-cks/scenario/playground).


- Install **Falco** on **Ubuntu**:

```bash
curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list

...

apt-get update -y
apt-get -y install linux-headers-$(uname -r)
apt-get install -y falco
falcoctl driver install
```

- Verify:

```bash
docker run --name ubuntu_bash --rm -i -t ubuntu bash
exit

...

cat /var/log/syslog | grep falco

```

- Now change the output on `falco_rules.yaml`:

```bash
vim /etc/falco/falco_rules.yaml

...

# On vim
/Terminal shell in container

# Modify 'output'
output: "%evt.time %container.id %container.name"
```

- Now restart the **Falco** service:

```bash
systemctl restart falco
```

- Check **Falco** is OK:

```bash
systemctl status falco
```

- Run a new **Pod**:

```bash
docker run --name demo --rm -i -t ubuntu bash
```

- Verify:

```bash
cat /var/log/syslog | grep falco | grep demo
```
</details>


<details>
<summary><h2>Problem 11 - Secrets</h2></summary>

- Create Secrets:

```bash
k create secret generic database --from-literal=username=sammy --from-literal=password=demo123
```

- Create a **Pod** to uses **Secrets** like **Volume**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: demo
spec:
  containers:
  - name: mypod
    image: redis
    volumeMounts:
    - name: sec-vol
      mountPath: "/etc/sec"
      readOnly: true
  volumes:
  - name: sec-vol
    secret:
      secretName: database
```

- Apply template:

```bash
k apply -f demo.yaml
```

- Verify:

```bash
k exec demo -- cat /etc/sec/username
k exec demo -- cat /etc/sec/password
```

- Save secrets to file:

```bash
k get secret database -o json | jq -r .data.username | base64 -d > sec
k get secret database -o json | jq -r .data.password | base64 -d >> sec
```

**NOTE:** Remember edit file via `vim` to add new line...

</details>


<details>
<summary><h2>Problem 12 - PodSecurity Policy</h2></summary>

- No more Valid for Kubernetes 1.26+

</details>

<details>
<summary><h2>Problem 13 - Security Context</h2></summary>

- Create a **Pod** with **SecurityContext**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: run
      mountPath: /var/run
    - name: log
      mountPath: /var/log/nginx
    - name: cache
      mountPath: /var/cache/nginx
  volumes:
  - name: run
    emptyDir: {}
  - name: log
    emptyDir: {}
  - name: cache
    emptyDir: {}
```

- Apply template:

```bash
k apply -f demo.yaml
```

- Verify:

```bash
k exec -it security-context-demo -- touch /tmp/test # <- KO
```
</details>

<details>
<summary><h2>Problem 14 - Privileged Pods</h2></summary>

- Create a **Privileged Pod**:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1001
    runAsGroup: 1001
  volumes:
  - name: sec-ctx-vol
    emptyDir: {}
  containers:
  - name: sec-ctx-demo
    image: busybox
    command: [ "sh", "-c", "sleep 1h" ]
    volumeMounts:
    - name: sec-ctx-vol
      mountPath: /data/demo
    securityContext:
      allowPrivilegeEscalation: false
```

- Apply template:

```bash
k apply -f demo.yaml
```

- Verify:

```bash
k exec -it security-context-demo -- id # uid=1001 gid=1001 groups=1001
```
</details>



<details>
<summary><h2>Problem 15 - Dockerfile Best Practices and Deployment Best Practices</h2></summary>

- If you have a privileged user used in a deployment then you would want
to remove it
- If you have secrets exposed in deployment you would want to remove it
- If you have a Dockerfile with secrets exposed or copied directly inside
the Dockerfile, you might want to remove it.
- If you have bad security contexts for the pods, you might want to
remove it.
- There can also be scenarios where you might be asked to edit the files
to make it according to the security best practices.

- More info [here](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
</details>

<details>
<summary><h2>Problem 16 - ImagePolicyWebhook</h2></summary>

- Create **AdmissionConfiguration** file:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: ImagePolicyWebhook
    configuration:
      imagePolicy:
        kubeConfigFile: <path-to-kubeconfig-file>
        allowTTL: 50
        denyTTL: 50
        retryBackoff: 500
        defaultAllow: true
```

- Create the `kubeconfig`file:

```yaml
clusters:
  - name: name-of-remote-imagepolicy-service
    cluster:
      certificate-authority: /path/to/ca.pem    # CA for verifying the remote service.
      server: https://images.example.com/policy # URL of remote service to query. Must use 'https'.

# users refers to the API server's webhook configuration.
users:
  - name: name-of-api-server
    user:
      client-certificate: /path/to/cert.pem # cert for the webhook admission controller to use
      client-key: /path/to/key.pem          # key matching the cert
```

- Modify `/etc/kubernetes/manifests/kube-apiserver.yaml` file:

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/demo/admission.json

...

  volumeMounts:
  - mountPath: /etc/kubernetes/demo
    name: admission
    readOnly: true
  volumes:
  - hostPath:
      path: /etc/kubernetes/demo
      type: DirectoryOrCreate
    name: policywebhook
```

- Verify:

```bash
kubectl run nginx --image=nginx # KO - Error from server (Forbidden): pods "nginx" is forbidden
```
</details>

</details>
