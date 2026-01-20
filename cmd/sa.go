package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"kam/internal/k8s"
	"kam/internal/profiles"
)

var saCmd = &cobra.Command{
	Use:   "sa",
	Short: "Manage ServiceAccounts (create/delete/get/list + RBAC bindings)",
}

func init() {
	saCmd.AddCommand(saCreateCmd)
	saCmd.AddCommand(saDeleteCmd)
	saCmd.AddCommand(saGetCmd)
	saCmd.AddCommand(saListCmd)

	addRoleFlag(saCreateCmd)
}

var saCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a ServiceAccount and bind a role profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, ok := profiles.Builtin(roleName)
		if !ok {
			return fmt.Errorf("unknown role profile %q (use view|edit|admin)", roleName)
		}
		if err := k8s.ValidateSafeRoleRef(p.ClusterRoleName); err != nil {
			return err
		}
		cl, err := k8s.Client()
		if err != nil {
			return err
		}
		plan := k8s.PlanCreateServiceAccount(namespace, args[0]) + "\n" +
			k8s.PlanCreateRoleBinding(namespace, k8s.BindingName("sa", args[0], namespace, p.Name), p.ClusterRoleName, "ServiceAccount", args[0], p.Name)
		if dryRun {
			fmt.Println(plan)
			return nil
		}
		if err := k8s.CreateOrUpdateServiceAccount(cl, namespace, args[0]); err != nil {
			return err
		}
		bindingName := k8s.BindingName("sa", args[0], namespace, p.Name)
		return k8s.CreateOrUpdateRoleBinding(cl, namespace, bindingName, p.ClusterRoleName, "ServiceAccount", args[0], p.Name)
	},
}

var saDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a ServiceAccount and kam-managed bindings for it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if dryRun {
			fmt.Printf("[dry-run] would delete ServiceAccount %s/%s and kam-managed bindings\n", namespace, args[0])
			return nil
		}
		cl, err := k8s.Client()
		if err != nil {
			return err
		}
		// Delete bindings first (sa subject)
		if err := k8s.RevokeSubjectInNamespace("ServiceAccount", args[0], namespace, false, false); err != nil {
			return err
		}
		return k8s.DeleteServiceAccount(cl, namespace, args[0])
	},
}

var saGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Show ServiceAccount and its bindings",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cl, err := k8s.Client()
		if err != nil {
			return err
		}
		_, err = cl.CoreV1().ServiceAccounts(namespace).Get(cmd.Context(), args[0], k8s.GetOptions())
		if err != nil {
			return err
		}
		items, err := k8s.FindBindingsBySubjectInNamespace(cl, "ServiceAccount", args[0], namespace)
		if err != nil {
			return err
		}
		sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
		fmt.Printf("ServiceAccount: %s/%s\n", namespace, args[0])
		fmt.Println("Bindings:")
		if len(items) == 0 {
			fmt.Println("- none")
			return nil
		}
		for _, it := range items {
			fmt.Printf("- %s %s\n", it.RoleRefKind, it.RoleRefName)
		}
		return nil
	},
}

var saListCmd = &cobra.Command{
	Use:   "list",
	Short: "List ServiceAccounts in a namespace (best-effort)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cl, err := k8s.Client()
		if err != nil {
			return err
		}
		lst, err := cl.CoreV1().ServiceAccounts(namespace).List(cmd.Context(), k8s.ListOptions())
		if err != nil {
			return err
		}
		names := make([]string, 0, len(lst.Items))
		for _, sa := range lst.Items {
			names = append(names, sa.Name)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Println(n)
		}
		return nil
	},
}
