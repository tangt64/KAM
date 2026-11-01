package identity

import (
	"context"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

type Credentials struct {
	Username string          `json:"username"`
	Password string          `json:"password"`
	Provider string          `json:"provider,omitempty"`
	Proof    json.RawMessage `json:"proof,omitempty"`
}
type ExternalIdentity struct{ Provider, Subject string }

// Providers verify credentials, never assign RBAC or choose an internal user ID.
// An OIDC provider can later validate issuer/audience/code+PKCE and return iss/sub.
// Linking that subject is an explicit administrator operation, never email matching.
type Provider interface {
	Name() string
	Authenticate(context.Context, Credentials, State) (ExternalIdentity, error)
}
type PasswordProvider struct{ dummy []byte }

func NewPasswordProvider() *PasswordProvider {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy-not-a-login-password"), bcrypt.DefaultCost)
	return &PasswordProvider{dummy: h}
}
func (p *PasswordProvider) Name() string { return "local" }
func (p *PasswordProvider) Authenticate(ctx context.Context, c Credentials, s State) (ExternalIdentity, error) {
	u, ok := s.Users[c.Username]
	h := p.dummy
	if ok && u.PasswordHash != "" {
		h = []byte(u.PasswordHash)
	}
	err := bcrypt.CompareHashAndPassword(h, []byte(c.Password))
	if err != nil || !ok || u.Disabled || u.Deleted {
		return ExternalIdentity{}, errors.New("invalid credentials")
	}
	return ExternalIdentity{Provider: "local", Subject: u.ID}, nil
}
