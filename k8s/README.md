# Intentionally insecure Kubernetes manifests (Aikido IaC demo)

Never apply these to a real cluster. Commit this folder to a repo connected to Aikido, or scan locally:

    pip install checkov && checkov -d . --framework kubernetes

| File | Issues demonstrated |
|---|---|
| 01-privileged-pod.yaml | privileged, root, host network/PID/IPC, hostPath `/`, Docker socket, SYS_ADMIN, `latest` tag, env secrets, no limits/probes |
| 02-deployment-no-hardening.yaml | no securityContext, untagged image, SA token automount, default namespace |
| 03-rbac-wildcard.yaml | wildcard ClusterRole, secrets read, pods/exec, cluster-admin bound to default SA |
| 04-services-secrets.yaml | public LoadBalancer 0.0.0.0/0, NodePort, plaintext Secret in git |
