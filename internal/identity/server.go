package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	authentication "k8s.io/api/authentication/v1"
)

const SubjectPrefix = "kiki-kam:"
const TokenPrefix = "kiki_"
const AdminGroup = "kiki-kam:account-admins"

var validName = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,62}$`)

func stringVersion(v int) string { return strconv.Itoa(v) }
func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func TokenHash(token string) string {
	d := sha256.Sum256([]byte(token))
	return hex.EncodeToString(d[:])
}
func passwordHash(password string) (string, error) {
	if len(password) < 12 || len(password) > 72 {
		return "", errors.New("password must contain 12..72 UTF-8 bytes")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}
func PublicUser(u User) map[string]any {
	return map[string]any{"id": u.ID, "name": u.Name, "subject": SubjectPrefix + u.ID, "disabled": u.Disabled, "deleted": u.Deleted, "admin": u.Admin}
}
func update(ctx context.Context, store Store, mutate func(*State) error) error {
	for i := 0; i < 8; i++ {
		s, v, err := store.Read(ctx)
		if err != nil {
			return err
		}
		if err = mutate(&s); err != nil {
			return err
		}
		err = store.CompareAndSwap(ctx, s, v)
		if !errors.Is(err, ErrConflict) {
			return err
		}
	}
	return ErrConflict
}
func Bootstrap(ctx context.Context, store Store, name, password string) error {
	if !validName.MatchString(name) {
		return errors.New("invalid username")
	}
	h, err := passwordHash(password)
	if err != nil {
		return err
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	return update(ctx, store, func(s *State) error {
		if len(s.Users) != 0 {
			return errors.New("bootstrap refused: identity store already initialized")
		}
		s.Users[name] = User{ID: id, Name: name, PasswordHash: h, Revision: 1, Admin: true, Identities: map[string]string{"local": id}}
		return nil
	})
}

type attempt struct {
	since time.Time
	count int
}
type Server struct {
	Store             Store
	Providers         map[string]Provider
	SessionTTL        time.Duration
	Audience          string
	WebhookClientName string
	Now               func() time.Time
	mu                sync.Mutex
	attempts          map[string]attempt
}

func NewServer(store Store, audience, webhookClient string) *Server {
	p := NewPasswordProvider()
	return &Server{Store: store, Providers: map[string]Provider{p.Name(): p}, SessionTTL: time.Hour, Audience: audience, WebhookClientName: webhookClient, Now: time.Now, attempts: map[string]attempt{}}
}
func (s *Server) limited(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	at := s.Now()
	for k, v := range s.attempts {
		if at.Sub(v.since) >= time.Minute {
			delete(s.attempts, k)
		}
	}
	v, ok := s.attempts[key]
	if !ok {
		if len(s.attempts) >= 4096 {
			return true
		}
		v = attempt{since: at}
	}
	v.count++
	s.attempts[key] = v
	return v.count > 20
}
func decode(r *http.Request, out any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("application/json required")
	}
	d := json.NewDecoder(io.LimitReader(r.Body, 8193))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("invalid request")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("invalid trailing request data")
	}
	return nil
}
func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
func (s *Server) resolve(state State, token string) (User, bool) {
	if !strings.HasPrefix(token, TokenPrefix) || len(token) != len(TokenPrefix)+43 {
		return User{}, false
	}
	session, ok := state.Sessions[TokenHash(token)]
	if !ok || session.Expires <= s.Now().Unix() {
		return User{}, false
	}
	for _, u := range state.Users {
		if u.ID == session.UserID && !u.Disabled && !u.Deleted && u.Revision == session.Revision {
			return u, true
		}
	}
	return User{}, false
}
func (s *Server) mutate(ctx context.Context, actor User, admin bool, fn func(*State) error) error {
	return update(ctx, s.Store, func(st *State) error {
		current, ok := st.Users[actor.Name]
		if !ok || current.ID != actor.ID || current.Revision != actor.Revision || current.Disabled || current.Deleted || (admin && !current.Admin) {
			return errors.New("account changed; sign in again")
		}
		return fn(st)
	})
}
func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(v, "Bearer ")
}
func audit(action, actor, target string) {
	log.Printf("identity action=%q actor=%q target=%q", action, actor, target)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		reply(w, 200, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/readyz" {
		state, _, err := s.Store.Read(r.Context())
		if err != nil || len(state.Users) == 0 {
			fail(w, 503, "identity store unavailable or not initialized")
			return
		}
		reply(w, 200, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path == "/authenticate" {
		s.webhook(w, r)
		return
	}
	if r.URL.Path == "/v1/login" {
		s.login(w, r)
		return
	}
	if token := bearer(r); !strings.HasPrefix(token, TokenPrefix) || len(token) != len(TokenPrefix)+43 {
		fail(w, 401, "authentication required")
		return
	}
	state, _, err := s.Store.Read(r.Context())
	if err != nil {
		fail(w, 503, "identity store unavailable")
		return
	}
	actor, ok := s.resolve(state, bearer(r))
	if !ok {
		fail(w, 401, "authentication required")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case path == "me" && r.Method == "GET":
		reply(w, 200, PublicUser(actor))
	case path == "logout" && r.Method == "POST":
		err = s.mutate(r.Context(), actor, false, func(st *State) error { delete(st.Sessions, TokenHash(bearer(r))); return nil })
		if err != nil {
			fail(w, 503, "logout not confirmed")
			return
		}
		audit("logout", actor.ID, actor.ID)
		reply(w, 200, map[string]bool{"revoked": true})
	case path == "password" && r.Method == "POST":
		s.changePassword(w, r, actor, actor.Name, false)
	case strings.HasPrefix(path, "identities/") && r.Method == "GET":
		u, exists := state.Users[strings.TrimPrefix(path, "identities/")]
		if !exists || u.Deleted {
			fail(w, 404, "user not found")
			return
		}
		reply(w, 200, map[string]string{"id": u.ID, "name": u.Name, "subject": SubjectPrefix + u.ID})
	case path == "users" && actor.Admin && r.Method == "GET":
		users := []map[string]any{}
		for _, u := range state.Users {
			users = append(users, PublicUser(u))
		}
		reply(w, 200, users)
	case path == "users" && actor.Admin && r.Method == "POST":
		s.createUser(w, r, actor)
	case strings.HasPrefix(path, "users/") && actor.Admin:
		s.manageUser(w, r, actor, strings.TrimPrefix(path, "users/"))
	default:
		fail(w, 403, "operation not permitted")
	}
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "POST required")
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if s.limited("ip:" + host) {
		fail(w, 429, "login rate limit exceeded")
		return
	}
	var c Credentials
	if decode(r, &c) != nil || len(c.Password) > 72 || len(c.Username) > 63 {
		fail(w, 400, "invalid login request")
		return
	}
	if s.limited("user:" + c.Username) {
		fail(w, 429, "login rate limit exceeded")
		return
	}
	if c.Provider == "" {
		c.Provider = "local"
	}
	provider, ok := s.Providers[c.Provider]
	if !ok {
		fail(w, 400, "authentication provider not configured")
		return
	}
	state, _, err := s.Store.Read(r.Context())
	if err != nil {
		fail(w, 503, "identity store unavailable")
		return
	}
	external, err := provider.Authenticate(r.Context(), c, state)
	if err == nil && (provider.Name() != c.Provider || external.Provider != c.Provider || external.Subject == "") {
		err = errors.New("invalid verified provider identity")
	}
	if err != nil {
		fail(w, 401, "invalid credentials")
		return
	}
	var actor User
	found := false
	for _, u := range state.Users {
		if u.Identities[external.Provider] == external.Subject && !u.Disabled && !u.Deleted {
			if found {
				fail(w, 503, "ambiguous identity mapping")
				return
			}
			actor = u
			found = true
		}
	}
	if !found {
		fail(w, 401, "identity not linked")
		return
	}
	random, err := randomID()
	if err != nil {
		fail(w, 503, "session unavailable")
		return
	}
	token := TokenPrefix + random
	expires := s.Now().Add(s.SessionTTL).Unix()
	err = update(r.Context(), s.Store, func(st *State) error {
		current, ok := st.Users[actor.Name]
		if !ok || current.ID != actor.ID || current.Revision != actor.Revision || current.Disabled || current.Deleted {
			return errors.New("account changed during login")
		}
		count := 0
		for hash, session := range st.Sessions {
			if session.Expires <= s.Now().Unix() {
				delete(st.Sessions, hash)
			} else if session.UserID == actor.ID {
				count++
			}
		}
		if count >= 5 {
			return errors.New("active session limit reached; log out or revoke sessions")
		}
		st.Sessions[TokenHash(token)] = Session{UserID: actor.ID, Revision: actor.Revision, Expires: expires}
		return nil
	})
	if err != nil {
		fail(w, 409, "session could not be created; account changed or session limit reached")
		return
	}
	audit("login", actor.ID, actor.ID)
	reply(w, 200, map[string]any{"token": token, "expires": expires, "user": PublicUser(actor)})
}
func (s *Server) createUser(w http.ResponseWriter, r *http.Request, actor User) {
	var in struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Admin    bool   `json:"admin"`
	}
	if decode(r, &in) != nil || !validName.MatchString(in.Name) {
		fail(w, 400, "invalid username/request")
		return
	}
	h, err := passwordHash(in.Password)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	id, err := randomID()
	if err != nil {
		fail(w, 503, "account unavailable")
		return
	}
	u := User{ID: id, Name: in.Name, PasswordHash: h, Revision: 1, Admin: in.Admin, Identities: map[string]string{"local": id}}
	err = s.mutate(r.Context(), actor, true, func(st *State) error {
		if old, ok := st.Users[in.Name]; ok && !old.Deleted {
			return errors.New("user already exists")
		}
		if len(st.Users) >= 500 {
			return errors.New("account capacity exceeded")
		}
		st.Users[in.Name] = u
		return nil
	})
	if err != nil {
		fail(w, 409, "user exists or capacity exceeded")
		return
	}
	audit("create", actor.ID, id)
	reply(w, 201, PublicUser(u))
}
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, actor User, name string, admin bool) {
	var in struct {
		Password    string `json:"password"`
		OldPassword string `json:"oldPassword,omitempty"`
	}
	if decode(r, &in) != nil {
		fail(w, 400, "invalid request")
		return
	}
	h, err := passwordHash(in.Password)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	err = s.mutate(r.Context(), actor, admin, func(st *State) error {
		u, ok := st.Users[name]
		if !ok || u.Deleted {
			return errors.New("user unavailable")
		}
		if !admin && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.OldPassword)) != nil {
			return errors.New("invalid current password")
		}
		u.PasswordHash = h
		u.Revision++
		st.Users[name] = u
		revoke(st, u.ID)
		return nil
	})
	if err != nil {
		fail(w, 409, "password update rejected")
		return
	}
	audit("password", actor.ID, name)
	reply(w, 200, map[string]bool{"sessionsRevoked": true})
}
func revoke(st *State, id string) {
	for h, v := range st.Sessions {
		if v.UserID == id {
			delete(st.Sessions, h)
		}
	}
}
func (s *Server) manageUser(w http.ResponseWriter, r *http.Request, actor User, path string) {
	bits := strings.Split(path, "/")
	name := bits[0]
	if len(bits) == 2 && bits[1] == "password" && r.Method == "POST" {
		s.changePassword(w, r, actor, name, true)
		return
	}
	action := ""
	if len(bits) == 1 && r.Method == "DELETE" {
		action = "delete"
	}
	if len(bits) == 2 && r.Method == "POST" {
		action = bits[1]
	}
	if action != "disable" && action != "enable" && action != "delete" && action != "revoke-sessions" && action != "link" {
		fail(w, 405, "unsupported account operation")
		return
	}
	var link struct {
		Provider string `json:"provider"`
		Subject  string `json:"subject"`
	}
	if action == "link" {
		if decode(r, &link) != nil || link.Provider == "local" || !validName.MatchString(link.Provider) || len(link.Subject) == 0 || len(link.Subject) > 512 {
			fail(w, 400, "invalid external identity link")
			return
		}
	}
	err := s.mutate(r.Context(), actor, true, func(st *State) error {
		u, ok := st.Users[name]
		if !ok || u.Deleted {
			return errors.New("user unavailable")
		}
		if u.Admin && (action == "disable" || action == "delete") {
			n := 0
			for _, v := range st.Users {
				if v.Admin && !v.Disabled && !v.Deleted {
					n++
				}
			}
			if n <= 1 {
				return errors.New("cannot remove final administrator")
			}
		}
		switch action {
		case "disable":
			u.Disabled = true
		case "enable":
			u.Disabled = false
		case "delete":
			u.Deleted = true
			u.Disabled = true
			u.PasswordHash = ""
			u.Identities = nil
		case "link":
			for _, v := range st.Users {
				if !v.Deleted && v.ID != u.ID && v.Identities[link.Provider] == link.Subject {
					return errors.New("external identity already linked")
				}
			}
			if u.Identities == nil {
				u.Identities = map[string]string{}
			}
			u.Identities[link.Provider] = link.Subject
		}
		u.Revision++
		st.Users[name] = u
		revoke(st, u.ID)
		return nil
	})
	if err != nil {
		fail(w, 409, "account update rejected")
		return
	}
	audit(action, actor.ID, name)
	reply(w, 200, map[string]bool{"updated": true, "sessionsRevoked": true})
}
func (s *Server) webhook(w http.ResponseWriter, r *http.Request) {
	// Only the dedicated, verified API-server client may submit TokenReviews.
	trusted := false
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 {
		trusted = subtle.ConstantTimeCompare([]byte(r.TLS.PeerCertificates[0].Subject.CommonName), []byte(s.WebhookClientName)) == 1
	}
	if !trusted {
		fail(w, 403, "API server client certificate required")
		return
	}
	if r.Method != "POST" {
		fail(w, 405, "POST required")
		return
	}
	var review authentication.TokenReview
	if decode(r, &review) != nil || review.APIVersion != "authentication.k8s.io/v1" || review.Kind != "TokenReview" {
		fail(w, 400, "TokenReview v1 required")
		return
	}
	out := authentication.TokenReview{TypeMeta: review.TypeMeta}
	// Reject native SA tokens without reading the API-backed store. This avoids
	// recursive webhook calls when SecretStore authenticates with its projected SA.
	if !strings.HasPrefix(review.Spec.Token, TokenPrefix) {
		reply(w, 200, out)
		return
	}
	matched := len(review.Spec.Audiences) == 0
	for _, aud := range review.Spec.Audiences {
		if aud == s.Audience {
			matched = true
			out.Status.Audiences = []string{s.Audience}
		}
	}
	if !matched {
		reply(w, 200, out)
		return
	}
	state, _, err := s.Store.Read(r.Context())
	if err != nil {
		fail(w, 503, "identity store unavailable")
		return
	}
	if u, ok := s.resolve(state, review.Spec.Token); ok {
		groups := []string{"kiki-kam:users"}
		if u.Admin {
			groups = append(groups, AdminGroup)
		}
		out.Status.Authenticated = true
		out.Status.User = authentication.UserInfo{Username: SubjectPrefix + u.ID, UID: u.ID, Groups: groups}
	}
	reply(w, 200, out)
}
func (s *Server) Validate() error {
	if s.Audience == "" || s.WebhookClientName == "" || s.SessionTTL < 5*time.Minute || s.SessionTTL > 24*time.Hour {
		return fmt.Errorf("audience/client name required; session lifetime must be 5m..24h")
	}
	return nil
}
