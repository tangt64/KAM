package k8s

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Guardrails: block extremely risky targets by default.
func ValidateSafeRoleRef(clusterRoleName string) error {
	// Block system:* and cluster-admin by default.
	if clusterRoleName == "cluster-admin" {
		return errors.New("refusing to bind cluster-admin by default")
	}
	if strings.HasPrefix(clusterRoleName, "system:") {
		return fmt.Errorf("refusing to bind %q (system roles are protected)", clusterRoleName)
	}
	return nil
}

func BindingName(prefix, subject, ns, profile string) string {
	base := fmt.Sprintf("kam-%s-%s-%s", prefix, sanitize(subject), profile)
	if ns == "" {
		return base
	}
	return fmt.Sprintf("%s-%s", base, sanitize(ns))
}

func BindingNameUnique(prefix, subject, ns, profile string) string {
	return BindingName(prefix, subject, ns, profile) + "-" + shortRand()
}

func sanitize(s string) string {
	// Keep it DNS-1123-ish, best effort.
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, ":", "-")
	return s
}

func shortRand() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func PlanCreateRoleBinding(ns, name, clusterRoleName, subjectKind, subjectName, profile string) string {
	scope := ScopeNS(ns)
	return fmt.Sprintf("[plan]\n- create/update RoleBinding %s/%s\n  roleRef: ClusterRole/%s\n  subject: %s/%s\n  labels: %s=%s, %s=%s, %s=%s, %s=%s\n",
		ns, name, clusterRoleName,
		subjectKind, subjectName,
		LabelManagedBy, ManagedByValue,
		LabelSubjectKind, subjectKind,
		LabelSubjectName, subjectName,
		LabelScope, scope,
	)
}

func PlanCreateServiceAccount(ns, name string) string {
	return fmt.Sprintf("[plan]\n- create/update ServiceAccount %s/%s\n  labels: %s=%s\n", ns, name, LabelManagedBy, ManagedByValue)
}

func CreateOrUpdateRoleBinding(cl *kubernetes.Clientset, ns, name, clusterRoleName, subjectKind, subjectName, profile string) error {
	ctx := context.Background()

	subject := rbacv1.Subject{Kind: subjectKind, Name: subjectName}
	if subjectKind == "ServiceAccount" {
		subject.Namespace = ns
	}

	lbls := Labels(subjectKind, subjectName, ScopeNS(ns), profile)

	desired := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    lbls,
		},
		RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: clusterRoleName},
		Subjects: []rbacv1.Subject{subject},
	}

	api := cl.RbacV1().RoleBindings(ns)
	cur, err := api.Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		// Update mutable fields
		cur.Labels = desired.Labels
		cur.RoleRef = desired.RoleRef
		cur.Subjects = desired.Subjects
		_, err = api.Update(ctx, cur, metav1.UpdateOptions{})
		return err
	}
	_, err = api.Create(ctx, desired, metav1.CreateOptions{})
	return err
}

func CreateOrUpdateServiceAccount(cl *kubernetes.Clientset, ns, name string) error {
	ctx := context.Background()
	api := cl.CoreV1().ServiceAccounts(ns)
	cur, err := api.Get(ctx, name, metav1.GetOptions{})
	lbls := map[string]string{LabelManagedBy: ManagedByValue}
	if err == nil {
		cur.Labels = merge(cur.Labels, lbls)
		_, err = api.Update(ctx, cur, metav1.UpdateOptions{})
		return err
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: lbls}}
	_, err = api.Create(ctx, sa, metav1.CreateOptions{})
	return err
}

func DeleteServiceAccount(cl *kubernetes.Clientset, ns, name string) error {
	return cl.CoreV1().ServiceAccounts(ns).Delete(context.Background(), name, metav1.DeleteOptions{})
}

func merge(dst, src map[string]string) map[string]string {
	if dst == nil {
		dst = map[string]string{}
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
