package audit

// ruleOrder lists every rule ID in a stable order (SARIF rules, validation of
// suppressions).
var ruleOrder = []string{
	"run-as-root",
	"privileged",
	"added-capability",
	"host-namespace",
	"host-path",
	"seccomp-unconfined",
	"allow-privilege-escalation",
	"writable-root-filesystem",
	"host-port",
	"missing-drop-all",
	"missing-seccomp",
}

// ruleDescriptions is the per-rule text used as the SARIF short description.
var ruleDescriptions = map[string]string{
	"run-as-root":                "Container may run as root: runAsNonRoot is not true",
	"privileged":                 "Container runs in privileged mode",
	"added-capability":           "Container adds a Linux capability beyond the safe baseline",
	"host-namespace":             "Pod shares a host namespace (hostNetwork, hostPID, or hostIPC)",
	"host-path":                  "Pod mounts a hostPath volume",
	"seccomp-unconfined":         "seccompProfile type is Unconfined",
	"allow-privilege-escalation": "allowPrivilegeEscalation is not false",
	"writable-root-filesystem":   "readOnlyRootFilesystem is not true",
	"host-port":                  "Container binds a hostPort",
	"missing-drop-all":           "capabilities.drop does not include ALL",
	"missing-seccomp":            "seccompProfile is not set at container or pod level",
}

// knownRule reports whether id is a rule this tool emits.
func knownRule(id string) bool {
	_, ok := ruleDescriptions[id]
	return ok
}

// podOnlyRules are reported on the pod, never on a container, so a
// container-scoped suppression cannot match them.
var podOnlyRules = map[string]bool{
	"host-namespace": true,
	"host-path":      true,
}
