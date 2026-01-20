package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"kam/internal/k8s"
)

var (
	kubeconfig string
	contextName string
	namespace string
	dryRun bool
	output string
)

var rootCmd = &cobra.Command{
	Use:   "kam",
	Short: "Kubernetes Account Manager (RBAC/ServiceAccount) - no external IdP",
	Long: `kam manages Kubernetes RBAC bindings and ServiceAccounts.

Important:
- Kubernetes does NOT store "User" objects.
- kam defines a logical user as: a subject name + RBAC bindings.
- "kam user create" means: declare the user and grant initial access (create RoleBinding/ClusterRoleBinding).
`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to ~/.kube/config)")
	rootCmd.PersistentFlags().StringVar(&contextName, "context", "", "Kubeconfig context name")
	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "default", "Namespace (when applicable)")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "Show actions without applying changes")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Output format: yaml|json|wide (best-effort)")

	cobra.OnInitialize(func() {
		k8s.SetGlobalKubeconfig(kubeconfig, contextName)
	})

	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(groupCmd)
	rootCmd.AddCommand(saCmd)
}
