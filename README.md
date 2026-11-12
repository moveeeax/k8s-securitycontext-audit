# k8s-securitycontext-audit

[![ci](https://github.com/moveeeax/k8s-securitycontext-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-securitycontext-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Kubernetes runs your container as **root** and lets it escalate privileges
unless you say otherwise. `k8s-securitycontext-audit` reads your manifests and
shows exactly which workloads ship without the guardrails or break node
isolation (host namespaces, `hostPath`, unconfined seccomp) — before they
reach a cluster. It is fully static and offline: it reads YAML files, never talks to a
cluster, so it is safe in CI and pre-commit.

## What it checks

| Rule | Severity | Trigger |
| --- | --- | --- |
| `run-as-root` | high | `runAsNonRoot` is not `true` (container or inherited pod level) |
| `privileged` | high | `privileged: true` |
| `added-capability` | high | a Linux capability added beyond the safe baseline (`NET_BIND_SERVICE`) |
| `host-namespace` | high | `hostNetwork`, `hostPID` or `hostIPC` is `true` (one finding per field, pod level) |
| `host-path` | high | a `hostPath` volume (names the path and volume, pod level) |
| `seccomp-unconfined` | high | `seccompProfile.type: Unconfined` at container or pod level |
| `allow-privilege-escalation` | medium | `allowPrivilegeEscalation` is not `false` |
| `writable-root-filesystem` | medium | `readOnlyRootFilesystem` is not `true` |
| `host-port` | medium | a container port with a non-zero `hostPort` |
| `missing-drop-all` | low | `capabilities.drop` does not include `ALL` |
| `missing-seccomp` | low | no `seccompProfile` at container or pod level |

Pod-level findings show `(pod)` in the container column and have an empty
`container` in JSON. A container `seccompProfile` overrides the pod one, so a
container with `RuntimeDefault` or `Localhost` under a pod without a profile
passes; a pod-level `Unconfined` is reported once even if every container
overrides it, matching the Pod Security Standards
[baseline](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
control.

It parses `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `Job`,
`CronJob`, and bare `Pod` manifests (including `initContainers`), and honors a
pod-level `securityContext` as the inherited default for its containers.

## How it works

Each YAML stream is split on document boundaries and decoded into a small typed
subset of the Kubernetes API — the `securityContext` fields plus host
namespaces, `hostPath` volumes, container ports and annotations — via
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

18 finding(s): 6 high, 6 medium, 6 low
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--output`, `-o` | `table` | `table`, `json`, or `sarif` |
| `--fail-on` | *(off)* | exit `1` if any unsuppressed finding is at or above `high`/`medium`/`low` |
| `--ignore-file` | *(none)* | YAML file of accepted findings, see [Suppressions](#suppressions) |

## Suppressions

Some workloads need what the audit flags: a CNI DaemonSet runs privileged
with `hostNetwork`, node-exporter mounts `/proc` and `/sys`. Accept those
findings explicitly instead of loosening `--fail-on` for the whole repo.
Suppressed findings stay in the output: the table lists them under
`Suppressed:`, JSON marks them `"suppressed": true` with a `suppression`
object (`source`, `reason`, `expires`), and SARIF adds a
[`suppressions`](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
entry with `status: accepted` and the reason as `justification` (`kind`
`inSource` for annotations, `external` for the ignore file). They are
counted as `summary.suppressed` and never trip `--fail-on`.

Annotations on the workload's own `metadata` (the Deployment, DaemonSet,
CronJob or Pod, not the pod template):

```yaml
metadata:
  annotations:
    # rules for every container and for the pod-level findings
    securitycontext-audit.moveeeax.io/ignore: "privileged,host-namespace"
    # rules for one container only
    securitycontext-audit.moveeeax.io/ignore.cilium-agent: "added-capability"
    # required: without it nothing is suppressed and a warning is printed
    securitycontext-audit.moveeeax.io/reason: "CNI agent manages node networking"
```

A container-scoped key only covers that container's findings; pod-level
rules (`host-namespace`, `host-path`, a pod-level `seccomp-unconfined`) need
the workload-wide key; `host-namespace` or `host-path` under a container key
is skipped with a warning, as are unknown rule names.
See [`examples/node-exporter-daemonset.yaml`](examples/node-exporter-daemonset.yaml).

`--ignore-file` keeps exceptions out of the manifests, e.g. for charts you
do not own:

```yaml
suppressions:
  - kind: DaemonSet
    namespace: kube-system      # must match exactly; omit only for resources without one
    name: cilium
    ignore: [host-namespace, host-path]
    reason: CNI agent manages node networking
  - kind: DaemonSet
    namespace: kube-system
    name: cilium
    container: cilium-agent     # optional; omit to cover the whole workload
    ignore: [privileged]
    reason: eBPF datapath needs a privileged agent
    expires: 2027-03-31         # optional; last day the entry applies (UTC)
```

The file is validated strictly: an unknown key, an unknown rule, a
pod-level rule under `container`, a missing `reason` or a malformed date is
an error (exit `2`). An entry past its
`expires` date stops suppressing and prints a warning, as does an entry that
matches no finding. Warnings go to stderr and into the JSON `warnings` array.

## CI gate

```yaml
- name: Audit securityContext
  run: |
    go install github.com/moveeeax/k8s-securitycontext-audit@latest
    k8s-securitycontext-audit audit ./k8s --fail-on high --output sarif > sec.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: sec.sarif
```

## License

MIT — see [LICENSE](LICENSE).
