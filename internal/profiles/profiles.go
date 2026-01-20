package profiles

// Profile maps a friendly role name to a Kubernetes ClusterRole reference.
// We keep it simple for MVP: view/edit/admin.
type Profile struct {
	Name            string
	ClusterRoleName string
}

func Builtin(name string) (Profile, bool) {
	switch name {
	case "view":
		return Profile{Name: "view", ClusterRoleName: "view"}, true
	case "edit":
		return Profile{Name: "edit", ClusterRoleName: "edit"}, true
	case "admin":
		// NOTE: Kubernetes built-in "admin" is namespace-scoped via RoleBinding to ClusterRole/admin.
		return Profile{Name: "admin", ClusterRoleName: "admin"}, true
	default:
		return Profile{}, false
	}
}
