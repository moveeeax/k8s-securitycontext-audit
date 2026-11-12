package audit

// Severity ranks a finding. Higher value means more severe.
type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
)

// String returns the lowercase name used in output.
func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "unknown"
	}
}

// ParseSeverity converts a name ("high"/"medium"/"low") to a Severity.
func ParseSeverity(name string) (Severity, bool) {
	switch name {
	case "high":
		return SeverityHigh, true
	case "medium":
		return SeverityMedium, true
	case "low":
		return SeverityLow, true
	default:
		return 0, false
	}
}

// Finding is a single securityContext gap on one container, or on the pod
// itself when Container is empty (host namespaces, hostPath volumes, a
// pod-level seccomp profile).
type Finding struct {
	Kind      string   `json:"kind"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name"`
	Container string   `json:"container"`
	Init      bool     `json:"init,omitempty"`
	Rule      string   `json:"rule"`
	Severity  Severity `json:"-"`
	// SeverityName mirrors Severity for JSON consumers.
	SeverityName string `json:"severity"`
	Message      string `json:"message"`
	File         string `json:"file,omitempty"`
	// Suppressed findings stay in the report but do not count toward the
	// summary or --fail-on. Suppression says who accepted them and why.
	Suppressed  bool         `json:"suppressed,omitempty"`
	Suppression *Suppression `json:"suppression,omitempty"`
}

// Suppression sources.
const (
	SourceAnnotation = "annotation"
	SourceIgnoreFile = "ignore-file"
)

// Suppression records why a finding was accepted.
type Suppression struct {
	// Source is SourceAnnotation or SourceIgnoreFile.
	Source string `json:"source"`
	Reason string `json:"reason"`
	// Expires is the ignore-file expiry date (YYYY-MM-DD), if any.
	Expires string `json:"expires,omitempty"`
}

// Report is the full audit result.
type Report struct {
	Findings []Finding      `json:"findings"`
	Summary  map[string]int `json:"summary"`
	// Warnings lists suppressions that were not applied (missing reason,
	// unknown rule, expired, unused).
	Warnings []string `json:"warnings,omitempty"`
}

// The typed manifest subset we decode. We deliberately model only the
// security-relevant fields rather than pulling in all of k8s.io/api.

type metadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations"`
}

type seccompProfile struct {
	// Type is RuntimeDefault, Localhost, or Unconfined.
	Type string `json:"type"`
}

type capabilities struct {
	Add  []string `json:"add"`
	Drop []string `json:"drop"`
}

type podSecurityContext struct {
	RunAsNonRoot   *bool           `json:"runAsNonRoot"`
	RunAsUser      *int64          `json:"runAsUser"`
	SeccompProfile *seccompProfile `json:"seccompProfile"`
}

type securityContext struct {
	RunAsNonRoot             *bool           `json:"runAsNonRoot"`
	RunAsUser                *int64          `json:"runAsUser"`
	Privileged               *bool           `json:"privileged"`
	AllowPrivilegeEscalation *bool           `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool           `json:"readOnlyRootFilesystem"`
	Capabilities             *capabilities   `json:"capabilities"`
	SeccompProfile           *seccompProfile `json:"seccompProfile"`
}

type containerPort struct {
	Name          string `json:"name"`
	ContainerPort int32  `json:"containerPort"`
	HostPort      int32  `json:"hostPort"`
	Protocol      string `json:"protocol"`
}

type container struct {
	Name            string           `json:"name"`
	SecurityContext *securityContext `json:"securityContext"`
	Ports           []containerPort  `json:"ports"`
}

type hostPathVolumeSource struct {
	Path string `json:"path"`
}

type volume struct {
	Name     string                `json:"name"`
	HostPath *hostPathVolumeSource `json:"hostPath"`
}

type podSpec struct {
	SecurityContext *podSecurityContext `json:"securityContext"`
	Containers      []container         `json:"containers"`
	InitContainers  []container         `json:"initContainers"`
	HostNetwork     bool                `json:"hostNetwork"`
	HostPID         bool                `json:"hostPID"`
	HostIPC         bool                `json:"hostIPC"`
	Volumes         []volume            `json:"volumes"`
}

type resource struct {
	Kind     string   `json:"kind"`
	Metadata metadata `json:"metadata"`
	Spec     struct {
		// Bare Pod: the pod spec fields sit directly under spec.
		podSpec
		// Deployment / StatefulSet / DaemonSet / ReplicaSet / Job
		Template *struct {
			Spec podSpec `json:"spec"`
		} `json:"template"`
		// CronJob
		JobTemplate *struct {
			Spec struct {
				Template struct {
					Spec podSpec `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

// podSpec extracts the pod template for any supported workload kind.
// The bool reports whether this kind carries a pod spec at all.
func (r *resource) podSpec() (podSpec, bool) {
	switch r.Kind {
	case "Pod":
		return r.Spec.podSpec, true
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job":
		if r.Spec.Template == nil {
			return podSpec{}, true
		}
		return r.Spec.Template.Spec, true
	case "CronJob":
		if r.Spec.JobTemplate == nil {
			return podSpec{}, true
		}
		return r.Spec.JobTemplate.Spec.Template.Spec, true
	default:
		return podSpec{}, false
	}
}
