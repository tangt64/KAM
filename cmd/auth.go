package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauth "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	"kam/internal/identity"
	"kam/internal/k8s"
	"kam/internal/login"
)

func password(c *cobra.Command, prompt string) (string, error) {
	stdin, _ := c.Flags().GetBool("password-stdin")
	if stdin {
		data, err := io.ReadAll(io.LimitReader(c.InOrStdin(), 1024))
		if err != nil {
			return "", err
		}
		if len(data) > 512 {
			return "", errors.New("password input too long")
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("use --password-stdin for non-interactive password input")
	}
	fmt.Fprint(c.ErrOrStderr(), prompt)
	data, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(c.ErrOrStderr())
	return string(data), err
}
func passwordFlag(c *cobra.Command) {
	c.Flags().Bool("password-stdin", false, "Read password from standard input; never from an argument")
}
func printJSON(c *cobra.Command, v any) error { return json.NewEncoder(c.OutOrStdout()).Encode(v) }
func profile() (login.Profile, error) {
	p, _, err := login.Current(kubeconfig, contextName)
	return p, err
}
func registerAuth() {
	loginCmd := &cobra.Command{Use: "login AUTH_HTTPS_ORIGIN", Short: "Sign in with ID/password and configure a Kubernetes context", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		name, _ := c.Flags().GetString("username")
		server, _ := c.Flags().GetString("server")
		caPath, _ := c.Flags().GetString("ca-file")
		apiCAPath, _ := c.Flags().GetString("api-ca-file")
		if name == "" {
			return errors.New("--username required")
		}
		if err := login.ValidURL(server); err != nil {
			return err
		}
		if err := login.ValidURL(args[0]); err != nil {
			return err
		}
		p := login.Profile{AuthURL: strings.TrimRight(args[0], "/"), APIServer: server}
		var err error
		if caPath != "" {
			p.CA, err = os.ReadFile(caPath)
			if err != nil {
				return err
			}
		}
		if apiCAPath != "" {
			p.APICA, err = os.ReadFile(apiCAPath)
			if err != nil {
				return err
			}
		}
		pass, err := password(c, "Password: ")
		if err != nil {
			return err
		}
		var signedIn struct {
			Token   string                             `json:"token"`
			Expires int64                              `json:"expires"`
			User    struct{ ID, Name, Subject string } `json:"user"`
		}
		if err = p.Request(c.Context(), "POST", "/v1/login", identity.Credentials{Username: name, Password: pass}, &signedIn); err != nil {
			return err
		}
		p.Token, p.Expires, p.User = signedIn.Token, signedIn.Expires, signedIn.User
		if err = p.VerifyAPI(c.Context()); err != nil {
			_ = p.Request(c.Context(), "POST", "/v1/logout", nil, nil)
			return err
		}
		p.Context = login.ContextName(server, p.User.ID)
		cache := login.CachePath(server, p.User.ID)
		if previous, readErr := login.Read(cache); readErr == nil && previous.Token != p.Token && previous.Expires > time.Now().Unix() {
			previous.AuthURL, previous.CA = p.AuthURL, p.CA
			if oldErr := previous.Request(c.Context(), "POST", "/v1/logout", nil, nil); oldErr != nil {
				fmt.Fprintln(c.ErrOrStderr(), "Previous session revocation could not be confirmed; an administrator can revoke remaining sessions.")
			}
		}
		if err = login.Save(cache, p); err != nil {
			_ = p.Request(c.Context(), "POST", "/v1/logout", nil, nil)
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		if err = login.Install(kubeconfig, cache, p, executable); err != nil {
			_ = p.Request(c.Context(), "POST", "/v1/logout", nil, nil)
			_ = os.Remove(cache)
			return err
		}
		fmt.Fprintf(c.OutOrStdout(), "Logged in as %s (context %s)\n", p.User.Name, p.Context)
		return nil
	}}
	loginCmd.Flags().String("username", "", "Login name")
	loginCmd.Flags().String("server", "", "Kubernetes HTTPS origin")
	loginCmd.Flags().String("ca-file", "", "Authentication service CA PEM")
	loginCmd.Flags().String("api-ca-file", "", "Kubernetes API CA PEM")
	passwordFlag(loginCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(&cobra.Command{Use: "whoami", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		p, err := profile()
		if err != nil {
			return err
		}
		var u any
		if err = p.Request(c.Context(), "GET", "/v1/me", nil, &u); err != nil {
			return err
		}
		if err = p.VerifyAPI(c.Context()); err != nil {
			return err
		}
		return printJSON(c, u)
	}})
	rootCmd.AddCommand(&cobra.Command{Use: "logout", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		p, cache, err := login.Current(kubeconfig, contextName)
		if err != nil {
			return err
		}
		remoteErr := p.Request(c.Context(), "POST", "/v1/logout", nil, nil)
		if err = login.RemoveConfig(kubeconfig, p); err != nil {
			return err
		}
		if err = os.Remove(cache); err != nil {
			return err
		}
		if remoteErr != nil {
			return errors.New("local login removed; server session revocation NOT confirmed")
		}
		fmt.Fprintln(c.OutOrStdout(), "Logged out; server session revoked (API webhook cache may briefly remain)")
		return nil
	}})
	credential := &cobra.Command{Use: "credential", Hidden: true, Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		path, _ := c.Flags().GetString("session-file")
		p, err := login.Read(path)
		if err != nil {
			return err
		}
		if p.Expires <= time.Now().Unix() {
			return errors.New("session expired; run kam login")
		}
		expiry := metav1.NewTime(time.Unix(p.Expires, 0))
		return printJSON(c, clientauth.ExecCredential{TypeMeta: metav1.TypeMeta{APIVersion: "client.authentication.k8s.io/v1", Kind: "ExecCredential"}, Status: &clientauth.ExecCredentialStatus{Token: p.Token, ExpirationTimestamp: &expiry}})
	}}
	credential.Flags().String("session-file", "", "Private login cache")
	rootCmd.AddCommand(credential)
	passwd := &cobra.Command{Use: "passwd", Short: "Change own password and revoke existing sessions", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		p, err := profile()
		if err != nil {
			return err
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("self password change requires a terminal")
		}
		old, err := password(c, "Current password: ")
		if err != nil {
			return err
		}
		next, err := password(c, "New password: ")
		if err != nil {
			return err
		}
		if err = p.Request(c.Context(), "POST", "/v1/password", map[string]string{"oldPassword": old, "password": next}, nil); err != nil {
			return err
		}
		fmt.Fprintln(c.OutOrStdout(), "Password changed; all sessions revoked. API caches may briefly retain access. Log in again.")
		return nil
	}}
	rootCmd.AddCommand(passwd)
	registerAccounts()
	registerGrants()
	registerServer()
}
func registerAccounts() {
	users := &cobra.Command{Use: "user", Short: "Manage actual KAM login accounts (account administrators only)"}
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		p, e := profile()
		if e != nil {
			return e
		}
		var out any
		if e = p.Request(c.Context(), "GET", "/v1/users", nil, &out); e != nil {
			return e
		}
		return printJSON(c, out)
	}}
	users.AddCommand(list)
	create := &cobra.Command{Use: "create USER", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		p, e := profile()
		if e != nil {
			return e
		}
		pass, e := password(c, "New user password: ")
		if e != nil {
			return e
		}
		admin, _ := c.Flags().GetBool("account-admin")
		var out any
		if e = p.Request(c.Context(), "POST", "/v1/users", map[string]any{"name": args[0], "password": pass, "admin": admin}, &out); e != nil {
			return e
		}
		return printJSON(c, out)
	}}
	passwordFlag(create)
	create.Flags().Bool("account-admin", false, "Grant account administration (not Kubernetes cluster-admin)")
	users.AddCommand(create)
	for _, action := range []string{"disable", "enable", "delete", "revoke-sessions", "passwd"} {
		action := action
		cmd := &cobra.Command{Use: action + " USER", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
			p, e := profile()
			if e != nil {
				return e
			}
			var previous map[string]string
			if action == "delete" || action == "disable" {
				if e = p.Request(c.Context(), "GET", "/v1/identities/"+url.PathEscape(args[0]), nil, &previous); e != nil {
					return e
				}
			}
			path := "/v1/users/" + url.PathEscape(args[0])
			method := "POST"
			var body any
			if action == "delete" {
				method = "DELETE"
			} else if action == "passwd" {
				pass, e := password(c, "New user password: ")
				if e != nil {
					return e
				}
				body = map[string]string{"password": pass}
				path += "/password"
			} else {
				path += "/" + action
			}
			if e = p.Request(c.Context(), method, path, body, nil); e != nil {
				return e
			}
			if previous != nil {
				if e = removeUserGrants(c.Context(), previous["subject"]); e != nil {
					return fmt.Errorf("account disabled/deleted and sessions revoked, but KAM grant cleanup failed: %w", e)
				}
			}
			fmt.Fprintln(c.OutOrStdout(), "Account operation complete; sessions invalidated where applicable.")
			return nil
		}}
		if action == "passwd" {
			passwordFlag(cmd)
		}
		users.AddCommand(cmd)
	}
	link := &cobra.Command{Use: "link USER", Short: "Explicitly map a future verified external provider subject", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		p, e := profile()
		if e != nil {
			return e
		}
		provider, _ := c.Flags().GetString("provider")
		subject, _ := c.Flags().GetString("subject")
		return p.Request(c.Context(), "POST", "/v1/users/"+url.PathEscape(args[0])+"/link", map[string]string{"provider": provider, "subject": subject}, nil)
	}}
	link.Flags().String("provider", "", "Provider key")
	link.Flags().String("subject", "", "Immutable external identity; OIDC adapter must bind issuer and sub")
	users.AddCommand(link)
	rootCmd.AddCommand(users)
}
func kubectl(c *cobra.Command, words []string, body any) error {
	argv := []string{}
	if kubeconfig != "" {
		argv = append(argv, "--kubeconfig", kubeconfig)
	}
	if contextName != "" {
		argv = append(argv, "--context", contextName)
	}
	argv = append(argv, words...)
	cmd := exec.CommandContext(c.Context(), "kubectl", argv...)
	cmd.Stdout = c.OutOrStdout()
	cmd.Stderr = c.ErrOrStderr()
	if body != nil {
		data, e := json.Marshal(body)
		if e != nil {
			return e
		}
		cmd.Stdin = strings.NewReader(string(data))
	}
	return cmd.Run()
}
func registerGrants() {
	for _, action := range []string{"grant", "revoke"} {
		action := action
		cmd := &cobra.Command{Use: action + " USER", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
			p, e := profile()
			if e != nil {
				return e
			}
			var user map[string]string
			if e = p.Request(c.Context(), "GET", "/v1/identities/"+url.PathEscape(args[0]), nil, &user); e != nil {
				return e
			}
			role, _ := c.Flags().GetString("profile")
			if role != "view" && role != "edit" && role != "admin" {
				return errors.New("profile must be view/edit/admin")
			}
			if namespace == "kam-system" || strings.HasPrefix(namespace, "kube-") {
				return errors.New("protected namespace")
			}
			name := "user-" + identity.TokenHash(user["subject"] + "\x00" + role)[:32]
			if action == "revoke" {
				return kubectl(c, []string{"-n", namespace, "delete", "kamaccessgrant", name}, nil)
			}
			spec := map[string]any{"subject": map[string]string{"kind": "User", "name": user["subject"]}, "profile": role}
			expiry, _ := c.Flags().GetString("expires-at")
			if expiry != "" {
				spec["expiresAt"] = expiry
			}
			obj := map[string]any{"apiVersion": "access.kam.dustbox.kr/v1alpha1", "kind": "KamAccessGrant", "metadata": map[string]string{"name": name, "namespace": namespace}, "spec": spec}
			argv := []string{"-n", namespace, "apply", "-f", "-"}
			if dryRun {
				argv = append(argv, "--dry-run=server")
			}
			if e = kubectl(c, argv, obj); e != nil {
				return e
			}
			if dryRun {
				return nil
			}
			return kubectl(c, []string{"-n", namespace, "wait", "--for=condition=Ready", "kamaccessgrant/" + name, "--timeout=90s"}, nil)
		}}
		cmd.Flags().String("profile", "view", "Namespace RBAC profile")
		cmd.Flags().String("expires-at", "", "Optional RFC3339 expiry")
		rootCmd.AddCommand(cmd)
	}
	rootCmd.AddCommand(&cobra.Command{Use: "permissions", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		return kubectl(c, []string{"auth", "can-i", "--list", "-n", namespace}, nil)
	}})
	rootCmd.AddCommand(&cobra.Command{Use: "get", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		return kubectl(c, []string{"get", "kamaccessgrants", "-n", namespace}, nil)
	}})
	ns := &cobra.Command{Use: "namespace", Short: "Inspect namespaces or select one; never create/delete namespaces"}
	ns.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error { return kubectl(c, []string{"get", "namespaces"}, nil) }})
	ns.AddCommand(&cobra.Command{Use: "use NAME", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		p, e := profile()
		if e != nil {
			return e
		}
		return kubectl(c, []string{"config", "set-context", p.Context, "--namespace", args[0]}, nil)
	}})
	rootCmd.AddCommand(ns)
}
func registerServer() {
	bootstrap := &cobra.Command{Use: "bootstrap", Short: "Initialize first account admin using existing Kubernetes admin credentials", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		cl, e := k8s.Client()
		if e != nil {
			return e
		}
		name, _ := c.Flags().GetString("username")
		pass, e := password(c, "Initial admin password: ")
		if e != nil {
			return e
		}
		ns, _ := c.Flags().GetString("state-namespace")
		secret, _ := c.Flags().GetString("state-secret")
		if e = identity.Bootstrap(c.Context(), identity.SecretStore{Client: cl, Namespace: ns, Name: secret}, name, pass); e != nil {
			return e
		}
		fmt.Fprintln(c.OutOrStdout(), "Initial account administrator created; password is not retained by the CLI")
		return nil
	}}
	bootstrap.Flags().String("username", "", "Initial administrator login")
	bootstrap.Flags().String("state-namespace", "kam-system", "Protected identity namespace")
	bootstrap.Flags().String("state-secret", "kiki-kam-identities", "Pre-created state Secret")
	passwordFlag(bootstrap)
	rootCmd.AddCommand(bootstrap)
	serve := &cobra.Command{Use: "serve", Short: "Serve HTTPS password login and mTLS TokenReview webhook", Args: cobra.NoArgs, RunE: func(c *cobra.Command, args []string) error {
		cl, e := k8s.Client()
		if e != nil {
			return e
		}
		get := func(key string) string { v, _ := c.Flags().GetString(key); return v }
		ca, e := os.ReadFile(get("webhook-client-ca"))
		if e != nil {
			return e
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return errors.New("invalid dedicated webhook client CA")
		}
		store := identity.SecretStore{Client: cl, Namespace: get("state-namespace"), Name: get("state-secret")}
		handler := identity.NewServer(store, get("audience"), get("webhook-client-name"))
		handler.SessionTTL, _ = c.Flags().GetDuration("session-ttl")
		if e = handler.Validate(); e != nil {
			return e
		}
		server := &http.Server{Addr: get("listen"), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}}
		ctx, cancel := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		go func() {
			<-ctx.Done()
			deadline, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			_ = server.Shutdown(deadline)
		}()
		e = server.ListenAndServeTLS(get("tls-cert"), get("tls-key"))
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	}}
	for key, value := range map[string]string{"listen": ":8443", "state-namespace": "kam-system", "state-secret": "kiki-kam-identities", "tls-cert": "/tls/tls.crt", "tls-key": "/tls/tls.key", "webhook-client-ca": "/webhook/ca.crt", "webhook-client-name": "kiki-kam-apiserver", "audience": ""} {
		serve.Flags().String(key, value, key)
	}
	serve.Flags().Duration("session-ttl", time.Hour, "5m..24h session lifetime")
	rootCmd.AddCommand(serve)
}
