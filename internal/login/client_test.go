package login

import (
	"k8s.io/client-go/tools/clientcmd"
	api "k8s.io/client-go/tools/clientcmd/api"
	"os"
	"path/filepath"
	"testing"
)

func TestLoginConfigPreservesExistingContextsAndDoesNotEmbedToken(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config")
	cfg := api.NewConfig()
	cfg.Contexts["existing"] = &api.Context{Cluster: "original", AuthInfo: "original"}
	cfg.CurrentContext = "existing"
	if e := clientcmd.WriteToFile(*cfg, path); e != nil {
		t.Fatal(e)
	}
	p := Profile{AuthURL: "https://auth.example", APIServer: "https://api.example", Token: "secret-token", Context: "kiki-kam-test"}
	cache := filepath.Join(root, "cache", "session.json")
	if e := Save(cache, p); e != nil {
		t.Fatal(e)
	}
	if e := Install(path, cache, p, "/usr/bin/kam"); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(path)
	if string(data) == "" {
		t.Fatal("empty config")
	}
	config, _ := clientcmd.Load(data)
	if config.Contexts["existing"] == nil {
		t.Fatal("existing context removed")
	}
	if config.AuthInfos[p.Context].Token != "" {
		t.Fatal("bearer token embedded in kubeconfig")
	}
	got, _, e := Current(path, "")
	if e != nil || got.Token != p.Token {
		t.Fatal(e)
	}
	if e = RemoveConfig(path, p); e != nil {
		t.Fatal(e)
	}
	config, _, _ = LoadConfig(path)
	if config.Contexts["existing"] == nil || config.Contexts[p.Context] != nil {
		t.Fatal("logout changed unrelated context")
	}
}
func TestHTTPSOriginsOnly(t *testing.T) {
	for _, v := range []string{"http://auth.example", "https://user:password@auth.example", "https://auth.example/path", "https://auth.example?token=secret"} {
		if ValidURL(v) == nil {
			t.Fatal("unsafe auth origin accepted", v)
		}
	}
}
