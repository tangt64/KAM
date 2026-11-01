package login

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	authentication "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	api "k8s.io/client-go/tools/clientcmd/api"
)

type Profile struct {
	AuthURL   string                             `json:"authURL"`
	CA        []byte                             `json:"ca"`
	APIServer string                             `json:"apiServer"`
	APICA     []byte                             `json:"apiCA"`
	Token     string                             `json:"token"`
	Expires   int64                              `json:"expires"`
	User      struct{ ID, Name, Subject string } `json:"user"`
	Context   string                             `json:"context"`
}

func ValidURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return errors.New("a bare HTTPS origin is required")
	}
	return nil
}
func HTTPClient(ca []byte) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if len(ca) > 0 && !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid CA certificate")
	}
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("authentication redirects are refused") }, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}, nil
}
func (p Profile) Request(ctx context.Context, method, path string, body any, out any) error {
	if err := ValidURL(p.AuthURL); err != nil {
		return err
	}
	client, err := HTTPClient(p.CA)
	if err != nil {
		return err
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, p.AuthURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("authentication service connection/TLS failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("authentication service rejected request: HTTP %d", response.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(out)
	}
	return nil
}
func (p Profile) VerifyAPI(ctx context.Context) error {
	if err := ValidURL(p.APIServer); err != nil {
		return err
	}
	cl, err := kubernetes.NewForConfig(&rest.Config{Host: p.APIServer, BearerToken: p.Token, Timeout: 10 * time.Second, TLSClientConfig: rest.TLSClientConfig{CAData: p.APICA}})
	if err != nil {
		return err
	}
	result, err := cl.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authentication.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return errors.New("Kubernetes did not accept the login; verify webhook and API CA")
	}
	if result.Status.UserInfo.Username != p.User.Subject || result.Status.UserInfo.UID != p.User.ID {
		return errors.New("Kubernetes identity does not match login identity")
	}
	return nil
}
func DefaultCache() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kube", "kiki-kam")
}
func CachePath(server, username string) string {
	h := sha256.Sum256([]byte(server + "\x00" + username))
	return filepath.Join(DefaultCache(), hex.EncodeToString(h[:16])+".json")
}
func ContextName(server, username string) string {
	h := sha256.Sum256([]byte(server + "\x00" + username))
	return "kiki-kam-" + hex.EncodeToString(h[:8])
}
func Read(path string) (Profile, error) {
	var p Profile
	info, err := os.Lstat(path)
	if err != nil {
		return p, errors.New("login session missing; run kam login")
	}
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return p, errors.New("session must be a private regular file (0600)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(data, &p); err != nil {
		return p, errors.New("invalid session cache")
	}
	if err = ValidURL(p.AuthURL); err != nil {
		return p, err
	}
	return p, nil
}
func Save(path string, p Profile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("session directory must not be a symlink")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".session-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func LoadConfig(path string) (*api.Config, clientcmd.PathOptions, error) {
	options := *clientcmd.NewDefaultPathOptions()
	if path != "" {
		options.LoadingRules.ExplicitPath = path
	}
	c, err := options.GetStartingConfig()
	return c, options, err
}
func Install(path, cache string, p Profile, executable string) error {
	config, options, err := LoadConfig(path)
	if err != nil {
		return err
	}
	config.Clusters[p.Context] = &api.Cluster{Server: p.APIServer, CertificateAuthorityData: p.APICA}
	config.AuthInfos[p.Context] = &api.AuthInfo{Exec: &api.ExecConfig{APIVersion: "client.authentication.k8s.io/v1", Command: executable, Args: []string{"credential", "--session-file", cache}, InteractiveMode: api.NeverExecInteractiveMode}}
	config.Contexts[p.Context] = &api.Context{Cluster: p.Context, AuthInfo: p.Context, Namespace: "default"}
	config.CurrentContext = p.Context
	return clientcmd.ModifyConfig(&options, *config, false)
}
func Current(path, context string) (Profile, string, error) {
	config, _, err := LoadConfig(path)
	if err != nil {
		return Profile{}, "", err
	}
	if context == "" {
		context = config.CurrentContext
	}
	c := config.Contexts[context]
	if c == nil {
		return Profile{}, "", errors.New("no current KAM context")
	}
	u := config.AuthInfos[c.AuthInfo]
	if u == nil || u.Exec == nil || len(u.Exec.Args) != 3 || u.Exec.Args[0] != "credential" || u.Exec.Args[1] != "--session-file" {
		return Profile{}, "", errors.New("current context is not a KAM login")
	}
	cache := u.Exec.Args[2]
	p, err := Read(cache)
	if err == nil && (p.Context != context || c.AuthInfo != p.Context || c.Cluster != p.Context) {
		err = errors.New("KAM context ownership mismatch")
	}
	return p, cache, err
}
func RemoveConfig(path string, p Profile) error {
	config, options, err := LoadConfig(path)
	if err != nil {
		return err
	}
	if c := config.Contexts[p.Context]; c != nil && c.AuthInfo == p.Context && c.Cluster == p.Context {
		delete(config.Contexts, p.Context)
		usedAuth := false
		for _, other := range config.Contexts {
			if other.AuthInfo == p.Context {
				usedAuth = true
			}
		}
		if !usedAuth {
			delete(config.AuthInfos, p.Context)
		}
		used := false
		for _, c := range config.Contexts {
			if c.Cluster == p.Context {
				used = true
			}
		}
		if !used {
			delete(config.Clusters, p.Context)
		}
		if config.CurrentContext == p.Context {
			config.CurrentContext = ""
		}
	}
	return clientcmd.ModifyConfig(&options, *config, false)
}
