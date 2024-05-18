# CKS Notes


### Config Vim + Enviroment Vars

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


### Kube-Api Server Crash

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


### Kube-Api Server NodeRestriction

```bash
vim /etc/kubernetes/manifests/kube-apiserver.yaml add -> --enable-admission-plugins=NodeRestriction 
```

- Set label to node: 

```bash
ssh <connect-to-node-restrict>
export KUBECONFIG=/etc/kubernetes/kubelet.conf
k label nodes node-restriction.kubernetes.io/<some-key>=<some-value> 
```


### AppArmor

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


### Auditing Enable + Audit Logs

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


### Certificate Signing Request Sign Manually and Create New Context

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


## In case to used the API

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



### Self-Signed Certificate + Kubernetes Context

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


## CIS Brenchmarks fix ControlPlane

- To run kube-bench specific hosts:
```bash
kube-bench run --targets <node-name>
```

- To check a specific fix:
```bash
kube-brench run --targets <node-name> --check <fix-name>
```


### Container Hardening

```dockerfile
FROM ubuntu:20.04 # <- Set Version
RUN apt-get update && apt-get -y install curl # <- Remove layer cache
ENV URL https://google.com/this-will-fail?secret-token=
RUN rm -rf /usr/bin/bash # <- Remove Bash Access
CMD ["sh", "-c", "curl --head $URL=$TOKEN"] # <- Uses Env Var Instead Hardcode
```


### Container Image Footprint User

- Add on Dockerfile USER <username> to run process with this user and not user root



### Container Namespaces Docker

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


### ImagePolicyWebhook Setup

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


### Image Use Digest

- To run a Pod with image digest run this:

```bash
k run nginx-web --image=nginx@sha256:eb05700fe7baa6890b74278e39b66b2ed1326831f9ec3ed4bdc6361a4ac2f333
```

- To change in deployment:

```bash
k edit deploy chamo-deploy # <- Change -> image: httpd@sha256:c7b8040505e2e63eafc82d37148b687ff488bf6d25fc24c8bf01d71f5b457531
```


### Image Vulnerability Scanning Trivy

- To find image on pods in a particular ns:

```bash
k -n applications get pod -oyaml | grep image:
```

- To scan and find vulnerability:

```bash
trivy image nginx:1.19.1-alpine-perl | grep CVE-2021-28831
trivy image nginx:1.19.1-alpine-perl | grep CVE-2016-9841
```


### Immutability Readonly Filesystem

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


### Ingress Secure

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


### 
