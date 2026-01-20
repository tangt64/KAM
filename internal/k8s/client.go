package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	globalKubeconfig string
	globalContext    string
	cachedClient     *kubernetes.Clientset
)

func SetGlobalKubeconfig(path, contextName string) {
	globalKubeconfig = path
	globalContext = contextName
	cachedClient = nil
}

func Client() (*kubernetes.Clientset, error) {
	if cachedClient != nil {
		return cachedClient, nil
	}

	cfg, err := buildConfig()
	if err != nil {
		return nil, err
	}
	cl, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	cachedClient = cl
	return cl, nil
}

func buildConfig() (*rest.Config, error) {
	// In-cluster first
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}

	kc := globalKubeconfig
	if kc == "" {
		home, _ := os.UserHomeDir()
		kc = filepath.Join(home, ".kube", "config")
	}

	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kc}
	overrides := &clientcmd.ConfigOverrides{}
	if globalContext != "" {
		overrides.CurrentContext = globalContext
	}

	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}
	return cfg, nil
}

func Ctx() context.Context { return context.Background() }

func GetOptions() metav1.GetOptions { return metav1.GetOptions{} }
func ListOptions() metav1.ListOptions { return metav1.ListOptions{} }
