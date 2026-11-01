package cmd

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
	"time"
)

func removeUserGrants(ctx context.Context, subject string) error {
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loading.ExplicitPath = kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, &clientcmd.ConfigOverrides{CurrentContext: contextName}).ClientConfig()
	if err != nil {
		return err
	}
	cfg.Timeout = 10 * time.Second
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return err
	}
	gvr := schema.GroupVersionResource{Group: "access.kam.dustbox.kr", Version: "v1alpha1", Resource: "kamaccessgrants"}
	items, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, item := range items.Items {
		spec, _ := item.Object["spec"].(map[string]any)
		s, _ := spec["subject"].(map[string]any)
		if s["kind"] != "User" || s["name"] != subject {
			continue
		}
		uid, version := item.GetUID(), item.GetResourceVersion()
		if err = client.Resource(gvr).Namespace(item.GetNamespace()).Delete(ctx, item.GetName(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &version}}); err != nil {
			return fmt.Errorf("grant cleanup incomplete: %w", err)
		}
	}
	return nil
}
