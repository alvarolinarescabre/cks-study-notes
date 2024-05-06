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

### TLS - Ingress

- Create Self-Signed Certificate

```bash
openssl req -newkey rsa:2048 -nodes -keyout chamo.key -out chamo.csr
openssl x509 -req -signkey chamo.key -in chamo.csr -days 365 -out chamo.crt
openssl x509 -text -noout -in chamo.crt
```

- Create TLS Secret

```bash
kubectl create secret tls nginx-tls --key certs/chamo.key --cert certs/chamo.crt
```


