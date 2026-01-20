package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type BindingInfo struct {
	Name       string
	Namespace  string
	Scope      string // ns:<name> or cluster
	RoleRefKind string
	RoleRefName string
	Kind       string // RoleBinding or ClusterRoleBinding
}

func FindBindingsBySubject(cl *kubernetes.Clientset, subjectKind, subjectName string) ([]BindingInfo, error) {
	ctx := context.Background()
	out := []BindingInfo{}

	// RoleBindings across all namespaces
	rbs, err := cl.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, rb := range rbs.Items {
		if subjectMatches(rb.Subjects, subjectKind, subjectName, rb.Namespace) {
			out = append(out, BindingInfo{
				Name: rb.Name, Namespace: rb.Namespace, Scope: ScopeNS(rb.Namespace),
				RoleRefKind: rb.RoleRef.Kind, RoleRefName: rb.RoleRef.Name,
				Kind: "RoleBinding",
			})
		}
	}

	crbs, err := cl.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, crb := range crbs.Items {
		if subjectMatches(crb.Subjects, subjectKind, subjectName, "") {
			out = append(out, BindingInfo{
				Name: crb.Name, Namespace: "", Scope: ScopeCluster(),
				RoleRefKind: crb.RoleRef.Kind, RoleRefName: crb.RoleRef.Name,
				Kind: "ClusterRoleBinding",
			})
		}
	}
	return out, nil
}

func FindBindingsBySubjectInNamespace(cl *kubernetes.Clientset, subjectKind, subjectName, ns string) ([]BindingInfo, error) {
	ctx := context.Background()
	out := []BindingInfo{}
	rbs, err := cl.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, rb := range rbs.Items {
		if subjectMatches(rb.Subjects, subjectKind, subjectName, ns) {
			out = append(out, BindingInfo{
				Name: rb.Name, Namespace: ns, Scope: ScopeNS(ns),
				RoleRefKind: rb.RoleRef.Kind, RoleRefName: rb.RoleRef.Name,
				Kind: "RoleBinding",
			})
		}
	}
	return out, nil
}

func ListLogicalSubjects(cl *kubernetes.Clientset, subjectKind string) ([]string, error) {
	ctx := context.Background()
	seen := map[string]struct{}{}
	selector := fmt.Sprintf("%s=%s,%s=%s", LabelManagedBy, ManagedByValue, LabelSubjectKind, subjectKind)

	rbs, err := cl.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	for _, rb := range rbs.Items {
		name := rb.Labels[LabelSubjectName]
		if name != "" {
			seen[name] = struct{}{}
		}
	}

	crbs, err := cl.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	for _, crb := range crbs.Items {
		name := crb.Labels[LabelSubjectName]
		if name != "" {
			seen[name] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func subjectMatches(subjects []rbacv1.Subject, kind, name, ns string) bool {
	for _, s := range subjects {
		if s.Kind != kind || s.Name != name {
			continue
		}
		if kind == "ServiceAccount" {
			// SA matches only when namespaces match.
			if s.Namespace == ns {
				return true
			}
			continue
		}
		return true
	}
	return false
}

func RevokeSubjectInNamespace(kind, name, ns string, dryRun bool, force bool) error {
	cl, err := Client()
	if err != nil {
		return err
	}
	ctx := context.Background()

	// RoleBindings in ns
	rbs, err := cl.RbacV1().RoleBindings(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, rb := range rbs.Items {
		if !subjectMatches(rb.Subjects, kind, name, ns) {
			continue
		}
		if !force && rb.Labels[LabelManagedBy] != ManagedByValue {
			continue
		}
		if dryRun {
			fmt.Printf("[dry-run] delete RoleBinding %s/%s\n", ns, rb.Name)
			continue
		}
		_ = cl.RbacV1().RoleBindings(ns).Delete(ctx, rb.Name, metav1.DeleteOptions{})
	}
	return nil
}

func RevokeSubjectEverywhere(kind, name string, dryRun bool, force bool) error {
	cl, err := Client()
	if err != nil {
		return err
	}
	ctx := context.Background()

	// RoleBindings across all namespaces
	rbs, err := cl.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, rb := range rbs.Items {
		if !subjectMatches(rb.Subjects, kind, name, rb.Namespace) {
			continue
		}
		if !force && rb.Labels[LabelManagedBy] != ManagedByValue {
			continue
		}
		if dryRun {
			fmt.Printf("[dry-run] delete RoleBinding %s/%s\n", rb.Namespace, rb.Name)
			continue
		}
		_ = cl.RbacV1().RoleBindings(rb.Namespace).Delete(ctx, rb.Name, metav1.DeleteOptions{})
	}

	// ClusterRoleBindings
	crbs, err := cl.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, crb := range crbs.Items {
		if !subjectMatches(crb.Subjects, kind, name, "") {
			continue
		}
		if !force && crb.Labels[LabelManagedBy] != ManagedByValue {
			continue
		}
		if dryRun {
			fmt.Printf("[dry-run] delete ClusterRoleBinding %s\n", crb.Name)
			continue
		}
		_ = cl.RbacV1().ClusterRoleBindings().Delete(ctx, crb.Name, metav1.DeleteOptions{})
	}
	return nil
}

// Utility: best-effort subject label derivation (future).
func NormalizeSubject(kind, name string) (string, string) {
	kind = strings.TrimSpace(kind)
	name = strings.TrimSpace(name)
	return kind, name
}
