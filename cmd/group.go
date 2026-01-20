package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"kam/internal/k8s"
	"kam/internal/profiles"
)

var groupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage groups (RBAC subjects of kind Group)",
}

func init() {
	groupCmd.AddCommand(groupGrantCmd)
	groupCmd.AddCommand(groupRevokeCmd)
	groupCmd.AddCommand(groupGetCmd)
	groupCmd.AddCommand(groupListCmd)

	addRoleFlag(groupGrantCmd)
	groupRevokeCmd.Flags().Bool("all-namespaces", false, "Revoke in all namespaces")
}

var groupGrantCmd = &cobra.Command{
	Use:   "grant <groupname>",
	Short: "Grant access to a group",
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
		bindingName := k8s.BindingNameUnique("group", args[0], namespace, p.Name)
		plan := k8s.PlanCreateRoleBinding(namespace, bindingName, p.ClusterRoleName, "Group", args[0], p.Name)
		if dryRun {
			fmt.Println(plan)
			return nil
		}
		return k8s.CreateOrUpdateRoleBinding(cl, namespace, bindingName, p.ClusterRoleName, "Group", args[0], p.Name)
	},
}

var groupRevokeCmd = &cobra.Command{
	Use:   "revoke <groupname>",
	Short: "Revoke access (deletes kam-managed bindings)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		all, _ := cmd.Flags().GetBool("all-namespaces")
		if all {
			return k8s.RevokeSubjectEverywhere("Group", args[0], dryRun, false)
		}
		return k8s.RevokeSubjectInNamespace("Group", args[0], namespace, dryRun, false)
	},
}

var groupGetCmd = &cobra.Command{
	Use:   "get <groupname>",
	Short: "Show bindings for a group",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cl, err := k8s.Client()
		if err != nil {
			return err
		}
		items, err := k8s.FindBindingsBySubject(cl, "Group", args[0])
		if err != nil {
			return err
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Scope != items[j].Scope {
				return items[i].Scope < items[j].Scope
			}
			return items[i].Name < items[j].Name
		})
		fmt.Printf("Group: %s\n", args[0])
		fmt.Println("Bindings:")
		if len(items) == 0 {
			fmt.Println("- none")
			return nil
		}
		for _, it := range items {
			fmt.Printf("- %s: %s %s\n", it.Scope, it.RoleRefKind, it.RoleRefName)
		}
		return nil
	},
}

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List groups managed by kam (derived from kam-labeled bindings)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cl, err := k8s.Client()
		if err != nil {
			return err
		}
		groups, err := k8s.ListLogicalSubjects(cl, "Group")
		if err != nil {
			return err
		}
		sort.Strings(groups)
		for _, g := range groups {
			fmt.Println(g)
		}
		return nil
	},
}
