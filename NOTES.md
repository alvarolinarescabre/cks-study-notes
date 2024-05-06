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


### TLS - Ingress

- Create Self-Signed Certificate

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout chamo.key -out chamo.crt -subj "/CN=www.chamo.io/O=www.chamo.io"
```

- To check certificate:

```bash
openssl x509 -text -noout -in chamo.crt
```

- Create TLS Secret

```bash
kubectl create secret tls chamo-tls --key chamo.key --cert chamo.crt
```


