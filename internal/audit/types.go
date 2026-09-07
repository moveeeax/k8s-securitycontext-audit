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

// Finding is a single securityContext gap on one container.
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
}

// Report is the full audit result.
type Report struct {
	Findings []Finding      `json:"findings"`
	Summary  map[string]int `json:"summary"`
}

// The typed manifest subset we decode. We deliberately model only the
// securityContext-relevant fields rather than pulling in all of k8s.io/api.

type metadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type capabilities struct {
	Add  []string `json:"add"`
	Drop []string `json:"drop"`
}

type podSecurityContext struct {
	RunAsNonRoot *bool  `json:"runAsNonRoot"`
	RunAsUser    *int64 `json:"runAsUser"`
}

type securityContext struct {
	RunAsNonRoot             *bool         `json:"runAsNonRoot"`
	RunAsUser                *int64        `json:"runAsUser"`
	Privileged               *bool         `json:"privileged"`
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   *bool         `json:"readOnlyRootFilesystem"`
	Capabilities             *capabilities `json:"capabilities"`
}

type container struct {
	Name            string           `json:"name"`
	SecurityContext *securityContext `json:"securityContext"`
}

type podSpec struct {
	SecurityContext *podSecurityContext `json:"securityContext"`
	Containers      []container         `json:"containers"`
	InitContainers  []container         `json:"initContainers"`
}

type resource struct {
	Kind     string   `json:"kind"`
	Metadata metadata `json:"metadata"`
	Spec     struct {
		// Bare Pod
		SecurityContext *podSecurityContext `json:"securityContext"`
		Containers      []container         `json:"containers"`
		InitContainers  []container         `json:"initContainers"`
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
		return podSpec{
			SecurityContext: r.Spec.SecurityContext,
			Containers:      r.Spec.Containers,
			InitContainers:  r.Spec.InitContainers,
		}, true
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
