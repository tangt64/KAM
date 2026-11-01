package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"kam/internal/k8s"
)

var (
	kubeconfig  string
	contextName string
	namespace   string
	dryRun      bool
	output      string
)

var rootCmd = &cobra.Command{
	Use:     "kam",
	Version: "0.2.0",
	Short:   "KIKI KAM: password login, accounts and namespace RBAC",
	Long: `KIKI KAM manages password login accounts, sessions and namespace access.
Authentication uses a dedicated HTTPS service and Kubernetes TokenReview webhook.
Original RBAC-only commands are preserved under "kam legacy".
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

	legacy := &cobra.Command{Use: "legacy", Short: "Original KAM RBAC/ServiceAccount commands; no login accounts"}
	legacy.AddCommand(userCmd, groupCmd, saCmd)
	rootCmd.AddCommand(legacy)
	registerAuth()
}
