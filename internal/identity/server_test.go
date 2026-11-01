package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Server, string) {
	t.Helper()
	store := NewMemoryStore()
	if err := Bootstrap(context.Background(), store, "admin", "initial-password-123"); err != nil {
		t.Fatal(err)
	}
	s := NewServer(store, "test-cluster", "test-apiserver")
	return s, signIn(t, s, "admin", "initial-password-123")
}
func call(s *Server, method, path, token string, body any) (int, map[string]any) {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}
func signIn(t *testing.T, s *Server, name, password string) string {
	t.Helper()
	code, out := call(s, "POST", "/v1/login", "", Credentials{Username: name, Password: password})
	if code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	return out["token"].(string)
}
func create(t *testing.T, s *Server, admin, name string) string {
	t.Helper()
	code, out := call(s, "POST", "/v1/users", admin, map[string]any{"name": name, "password": "user-password-123"})
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	return out["id"].(string)
}
func review(s *Server, token, audience string, trusted bool) (int, map[string]any) {
	r := httptest.NewRequest("POST", "/authenticate", strings.NewReader(`{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"`+token+`","audiences":["`+audience+`"]}}`))
	r.Header.Set("Content-Type", "application/json")
	if trusted {
		cert := &x509.Certificate{Subject: pkix.Name{CommonName: "test-apiserver"}}
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}, PeerCertificates: []*x509.Certificate{cert}}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}
func authenticated(out map[string]any) bool {
	st, _ := out["status"].(map[string]any)
	v, _ := st["authenticated"].(bool)
	return v
}
func TestAccountLifecycleAndImmutableRecreation(t *testing.T) {
	s, admin := fixture(t)
	old := create(t, s, admin, "alice")
	token := signIn(t, s, "alice", "user-password-123")
	if code, _ := call(s, "GET", "/v1/users", token, nil); code != 403 {
		t.Fatal("regular user may manage accounts")
	}
	if code, _ := call(s, "POST", "/v1/users/alice/disable", admin, nil); code != 200 {
		t.Fatal(code)
	}
	if code, _ := call(s, "GET", "/v1/me", token, nil); code != 401 {
		t.Fatal("disabled session survived")
	}
	if code, _ := call(s, "POST", "/v1/login", "", Credentials{Username: "alice", Password: "user-password-123"}); code != 401 {
		t.Fatal("disabled user logged in")
	}
	call(s, "POST", "/v1/users/alice/enable", admin, nil)
	if code, _ := call(s, "GET", "/v1/me", token, nil); code != 401 {
		t.Fatal("enable revived old session")
	}
	token = signIn(t, s, "alice", "user-password-123")
	call(s, "DELETE", "/v1/users/alice", admin, nil)
	next := create(t, s, admin, "alice")
	if old == next {
		t.Fatal("deleted identity reused")
	}
	if code, _ := call(s, "GET", "/v1/me", token, nil); code != 401 {
		t.Fatal("old identity session survived recreation")
	}
}
func TestPasswordRotationLogoutAndNoSecretDisclosure(t *testing.T) {
	s, admin := fixture(t)
	create(t, s, admin, "alice")
	token := signIn(t, s, "alice", "user-password-123")
	code, out := call(s, "POST", "/v1/password", token, map[string]string{"oldPassword": "wrong", "password": "replacement-password-123"})
	if code != 409 {
		t.Fatal(code, out)
	}
	code, _ = call(s, "POST", "/v1/password", token, map[string]string{"oldPassword": "user-password-123", "password": "replacement-password-123"})
	if code != 200 {
		t.Fatal(code)
	}
	if code, _ = call(s, "GET", "/v1/me", token, nil); code != 401 {
		t.Fatal("rotation retained session")
	}
	next := signIn(t, s, "alice", "replacement-password-123")
	call(s, "POST", "/v1/logout", next, nil)
	if code, _ = call(s, "GET", "/v1/me", next, nil); code != 401 {
		t.Fatal("logout retained session")
	}
	state, _, _ := s.Store.Read(context.Background())
	data, _ := json.Marshal(state)
	if bytes.Contains(data, []byte(next)) || bytes.Contains(data, []byte("replacement-password-123")) {
		t.Fatal("plaintext secret stored")
	}
	_, out = call(s, "GET", "/v1/identities/alice", admin, nil)
	data, _ = json.Marshal(out)
	if bytes.Contains(data, []byte("Hash")) {
		t.Fatal("hash disclosed")
	}
}
func TestWebhookTrustAudienceAndExpiry(t *testing.T) {
	s, admin := fixture(t)
	if code, _ := review(s, admin, "test-cluster", false); code != 403 {
		t.Fatal("unauthenticated TokenReview allowed")
	}
	_, out := review(s, admin, "wrong-cluster", true)
	if authenticated(out) {
		t.Fatal("wrong audience accepted")
	}
	_, out = review(s, admin, "test-cluster", true)
	if !authenticated(out) {
		t.Fatal(out)
	}
	s.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	_, out = review(s, admin, "test-cluster", true)
	if authenticated(out) {
		t.Fatal("expired session accepted")
	}
}

type brokenStore struct{}

func (brokenStore) Read(context.Context) (State, string, error) {
	panic("native SA review must not access the API-backed store")
}
func (brokenStore) CompareAndSwap(context.Context, State, string) error { panic("not expected") }
func TestNativeSATokenCannotRecurseIntoSecretStore(t *testing.T) {
	s := NewServer(brokenStore{}, "test-cluster", "test-apiserver")
	_, out := review(s, "eyJ-native-SA-token", "test-cluster", true)
	if authenticated(out) {
		t.Fatal(out)
	}
}
func TestFinalAdminAndBootstrapAreProtected(t *testing.T) {
	s, admin := fixture(t)
	if code, _ := call(s, "POST", "/v1/users/admin/disable", admin, nil); code != 409 {
		t.Fatal("final admin disabled")
	}
	if err := Bootstrap(context.Background(), s.Store, "other", "other-password-123"); err == nil {
		t.Fatal("bootstrap overwrote accounts")
	}
}

type externalProvider struct{}

func (externalProvider) Name() string { return "future-oidc" }
func (externalProvider) Authenticate(context.Context, Credentials, State) (ExternalIdentity, error) {
	return ExternalIdentity{Provider: "future-oidc", Subject: "https://issuer.example#immutable-sub"}, nil
}
func TestProviderExtensionRequiresExplicitLink(t *testing.T) {
	s, admin := fixture(t)
	id := create(t, s, admin, "alice")
	s.Providers["future-oidc"] = externalProvider{}
	if code, _ := call(s, "POST", "/v1/login", "", Credentials{Provider: "future-oidc"}); code != 401 {
		t.Fatal("unlinked external identity accepted")
	}
	if code, _ := call(s, "POST", "/v1/users/alice/link", admin, map[string]string{"provider": "future-oidc", "subject": "https://issuer.example#immutable-sub"}); code != 200 {
		t.Fatal(code)
	}
	code, out := call(s, "POST", "/v1/login", "", Credentials{Provider: "future-oidc"})
	if code != 200 || out["user"].(map[string]any)["id"] != id {
		t.Fatal("provider changed identity", code, out)
	}
	if code, _ = call(s, "POST", "/v1/login", "", Credentials{Provider: "not-configured"}); code != 400 {
		t.Fatal("unknown provider accepted")
	}
}
func TestConcurrentSessionsAndStaleAdminCannotMutate(t *testing.T) {
	s, admin := fixture(t)
	_, out := call(s, "GET", "/v1/me", admin, nil)
	state, _, _ := s.Store.Read(context.Background())
	old := state.Users["admin"]
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := call(s, "POST", "/v1/login", "", Credentials{Username: "admin", Password: "initial-password-123"})
			if code != 200 {
				t.Error(code)
			}
		}()
	}
	wg.Wait()
	state, _, _ = s.Store.Read(context.Background())
	if len(state.Sessions) != 5 {
		t.Fatal("lost CAS session updates", len(state.Sessions), out)
	}
	call(s, "POST", "/v1/users/admin/revoke-sessions", admin, nil)
	if err := s.mutate(context.Background(), old, true, func(st *State) error { st.Users["evil"] = old; return nil }); err == nil {
		t.Fatal("stale admin mutation accepted")
	}
}
