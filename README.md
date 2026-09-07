# k8s-securitycontext-audit

[![ci](https://github.com/moveeeax/k8s-securitycontext-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-securitycontext-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Kubernetes runs your container as **root** and lets it escalate privileges
unless you say otherwise. `k8s-securitycontext-audit` reads your manifests and
shows exactly which workloads ship without the guardrails — before they reach a
cluster. It is fully static and offline: it reads YAML files, never talks to a
cluster, so it is safe in CI and pre-commit.

## What it checks

| Rule | Severity | Trigger |
| --- | --- | --- |
| `run-as-root` | high | `runAsNonRoot` is not `true` (container or inherited pod level) |
| `privileged` | high | `privileged: true` |
| `added-capability` | high | a Linux capability added beyond the safe baseline (`NET_BIND_SERVICE`) |
| `allow-privilege-escalation` | medium | `allowPrivilegeEscalation` is not `false` |
| `writable-root-filesystem` | medium | `readOnlyRootFilesystem` is not `true` |
| `missing-drop-all` | low | `capabilities.drop` does not include `ALL` |

It parses `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `Job`,
`CronJob`, and bare `Pod` manifests (including `initContainers`), and honors a
pod-level `securityContext` as the inherited default for its containers.

## How it works

Each YAML stream is split on document boundaries and decoded into a small typed
subset of the Kubernetes API — just the `securityContext` fields — via
`sigs.k8s.io/yaml`. That keeps the binary tiny and the classifier pure: every
check runs in memory with no cluster access. Non-workload kinds (ConfigMaps,
Services, …) are skipped.

## Install

```shell
go install github.com/moveeeax/k8s-securitycontext-audit@latest
```

Or build from source:

```shell
git clone https://github.com/moveeeax/k8s-securitycontext-audit
cd k8s-securitycontext-audit
go build -o k8s-securitycontext-audit .
```

## Usage

```shell
# Audit every manifest under ./k8s
k8s-securitycontext-audit audit ./k8s

# JSON for a dashboard
k8s-securitycontext-audit audit ./k8s --output json > sec.json

# Fail the pipeline on any high-severity gap, emit SARIF
k8s-securitycontext-audit audit ./k8s --fail-on high --output sarif > sec.sarif

# Read from stdin (e.g. helm template | ...)
helm template ./chart | k8s-securitycontext-audit audit -
```

Example against the bundled insecure manifest:

```console
$ k8s-securitycontext-audit audit examples/insecure-deployment.yaml
SEVERITY  RESOURCE             CONTAINER    RULE                        MESSAGE
high      Deployment prod/web  app          run-as-root                 container may run as root: runAsNonRoot is not set to true (container or pod level)
high      Deployment prod/web  sidecar      privileged                  container runs in privileged mode
high      Deployment prod/web  sidecar      added-capability            adds Linux capability "SYS_ADMIN" beyond the safe baseline
...

15 finding(s): 6 high, 6 medium, 3 low
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--output`, `-o` | `table` | `table`, `json`, or `sarif` |
| `--fail-on` | *(off)* | exit `1` if any finding is at or above `high`/`medium`/`low` |

## CI gate

```yaml
- name: Audit securityContext
  run: |
    go install github.com/moveeeax/k8s-securitycontext-audit@latest
    k8s-securitycontext-audit audit ./k8s --fail-on high --output sarif > sec.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sec.sarif
```

## License

MIT — see [LICENSE](LICENSE).
