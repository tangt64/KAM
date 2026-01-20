package k8s

import "fmt"

const (
	LabelManagedBy   = "app.kam/managed-by"
	LabelSubjectKind = "app.kam/subject-kind"
	LabelSubjectName = "app.kam/subject-name"
	LabelScope       = "app.kam/scope"
	LabelProfile     = "app.kam/profile"
	ManagedByValue   = "kam"
)

func Labels(subjectKind, subjectName, scope, profile string) map[string]string {
	m := map[string]string{
		LabelManagedBy:   ManagedByValue,
		LabelSubjectKind: subjectKind,
		LabelSubjectName: subjectName,
		LabelScope:       scope,
	}
	if profile != "" {
		m[LabelProfile] = profile
	}
	return m
}

// ScopeNS returns a label-safe namespace scope value.
//
// IMPORTANT:
// Kubernetes label *values* cannot contain ':' (colon).
// Previous versions used "ns:<namespace>", which causes errors like:
//
//	Invalid value: "ns:test1": a valid label must be ...
//
// We keep the meaning but replace ':' with a label-safe separator.
// Example: ns:test1 -> ns.test1
func ScopeNS(ns string) string {
	if ns == "" {
		return "ns"
	}
	return fmt.Sprintf("ns.%s", sanitize(ns))
}
func ScopeCluster() string { return "cluster" }
