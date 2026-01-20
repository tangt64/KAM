package cmd

import (
	"errors"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"kam/internal/k8s"
	"kam/internal/profiles"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage logical users (RBAC subjects of kind User)",
}

func init() {
	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userGrantCmd)
	userCmd.AddCommand(userSetCmd)
	userCmd.AddCommand(userRevokeCmd)
	userCmd.AddCommand(userDeleteCmd)
	userCmd.AddCommand(userGetCmd)
	userCmd.AddCommand(userListCmd)

	addRoleFlag(userCreateCmd)
	addRoleFlag(userGrantCmd)
	addRoleFlag(userSetCmd)

	userRevokeCmd.Flags().Bool("all-namespaces", false, "Revoke in all namespaces")
	userDeleteCmd.Flags().Bool("force", false, "Also remove non-kam bindings that match the subject (dangerous)")
}

var roleName string

func addRoleFlag(c *cobra.Command) {
	c.Flags().StringVar(&roleName, "role", "view", "Role profile: view|edit|admin")
}

func mustProfile() (profiles.Profile, error) {
	p, ok := profiles.Builtin(roleName)
	if !ok {
		return profiles.Profile{}, fmt.Errorf("unknown role profile %q (use view|edit|admin)", roleName)
	}
	return p, nil
}

var userCreateCmd = &cobra.Command{
	Use:   "create <username>",
	Short: "Declare a logical user and grant initial access",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := mustProfile()
		if err != nil {
			return err
		}
		return upsertUserBinding(args[0], p, true)
	},
}

var userGrantCmd = &cobra.Command{
	Use:   "grant <username>",
	Short: "Grant additional access (creates an extra binding)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := mustProfile()
		if err != nil {
			return err
		}
		return upsertUserBinding(args[0], p, false)
	},
}

var userSetCmd = &cobra.Command{
	Use:   "set <username>",
	Short: "Replace access in a namespace (revoke then grant)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := mustProfile()
		if err != nil {
			return err
		}
		// Revoke in the current namespace only, then grant one binding.
		if err := k8s.RevokeSubjectInNamespace("User", args[0], namespace, dryRun, false); err != nil {
			return err
		}
		return upsertUserBinding(args[0], p, true)
	},
}

var userRevokeCmd = &cobra.Command{
	Use:   "revoke <username>",
	Short: "Revoke access (deletes kam-managed bindings)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		all, _ := cmd.Flags().GetBool("all-namespaces")
		if all {
			return k8s.RevokeSubjectEverywhere("User", args[0], dryRun, false)
		}
		return k8s.RevokeSubjectInNamespace("User", args[0], namespace, dryRun, false)
	},
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete <username>",
	Short: "Remove the logical user (revoke all access)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		return k8s.RevokeSubjectEverywhere("User", args[0], dryRun, force)
	},
}

var userGetCmd = &cobra.Command{
	Use:   "get <username>",
	Short: "Show bindings for a logical user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cl, err := k8s.Client()
		if err != nil {
			return err
		}
		items, err := k8s.FindBindingsBySubject(cl, "User", args[0])
		if err != nil {
			return err
		}
		if len(items) == 0 {
			fmt.Printf("User (logical): %s\nBindings: none\nStatus: not-registered (no RBAC bindings found)\n", args[0])
			return nil
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Scope != items[j].Scope {
				return items[i].Scope < items[j].Scope
			}
			return items[i].Name < items[j].Name
		})
		fmt.Printf("User (logical): %s\n", args[0])
		fmt.Println("Bindings:")
		for _, it := range items {
			fmt.Printf("- %s: %s %s\n", it.Scope, it.RoleRefKind, it.RoleRefName)
		}
		fmt.Println("Status: active")
		return nil
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List logical users managed by kam (derived from kam-labeled bindings)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cl, err := k8s.Client()
		if err != nil {
			return err
		}
		users, err := k8s.ListLogicalSubjects(cl, "User")
		if err != nil {
			return err
		}
		sort.Strings(users)
		for _, u := range users {
			fmt.Println(u)
		}
		return nil
	},
}

func upsertUserBinding(username string, p profiles.Profile, singlePerNS bool) error {
	if username == "" {
		return errors.New("username is required")
	}
	if err := k8s.ValidateSafeRoleRef(p.ClusterRoleName); err != nil {
		return err
	}

	cl, err := k8s.Client()
	if err != nil {
		return err
	}

	// For "create" we want a deterministic name; for "grant" we allow multiple bindings.
	bindingName := k8s.BindingName("user", username, namespace, p.Name)
	if !singlePerNS {
		bindingName = k8s.BindingNameUnique("user", username, namespace, p.Name)
	}

	plan := k8s.PlanCreateRoleBinding(namespace, bindingName, p.ClusterRoleName, "User", username, p.Name)
	if dryRun {
		fmt.Println(plan)
		return nil
	}

	return k8s.CreateOrUpdateRoleBinding(cl, namespace, bindingName, p.ClusterRoleName, "User", username, p.Name)
}
