# k8s-securitycontext-audit
CLI that statically audits Kubernetes manifests for missing or weak securityContext (root, privileged, allowPrivilegeEscalation, writable rootfs, dangerous capabilities), with table/JSON/SARIF output and a CI gate.
