// Package identity owns accounts and sessions. RBAC remains a Kubernetes concern.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var ErrConflict = errors.New("concurrent identity update")

type User struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	PasswordHash string `json:"passwordHash,omitempty"`
	Revision     int64  `json:"revision"`
	Disabled     bool   `json:"disabled"`
	Deleted      bool   `json:"deleted"`
	Admin        bool   `json:"admin"`
	// Keys are provider names; values are immutable, verified provider subjects.
	Identities map[string]string `json:"identities,omitempty"`
}
type Session struct {
	UserID   string `json:"userID"`
	Revision int64  `json:"revision"`
	Expires  int64  `json:"expires"`
}
type State struct {
	Schema   int                `json:"schema"`
	Users    map[string]User    `json:"users"`
	Sessions map[string]Session `json:"sessions"`
}

func Empty() State { return State{Schema: 1, Users: map[string]User{}, Sessions: map[string]Session{}} }

type Store interface {
	Read(context.Context) (State, string, error)
	CompareAndSwap(context.Context, State, string) error
}

// SecretStore supports multiple replicas without a password database server.
// resourceVersion provides optimistic concurrency. The service needs access to
// one pre-created Secret only, never arbitrary cluster Secrets.
type SecretStore struct {
	Client          kubernetes.Interface
	Namespace, Name string
}

func (s SecretStore) Read(ctx context.Context) (State, string, error) {
	secret, err := s.Client.CoreV1().Secrets(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if err != nil {
		return State{}, "", err
	}
	state := Empty()
	if data := secret.Data["state.json"]; len(data) > 0 {
		if err = json.Unmarshal(data, &state); err != nil {
			return State{}, "", errors.New("invalid identity state")
		}
	}
	if state.Schema != 1 || state.Users == nil || state.Sessions == nil {
		return State{}, "", errors.New("unsupported identity schema")
	}
	return state, secret.ResourceVersion, nil
}
func (s SecretStore) CompareAndSwap(ctx context.Context, state State, version string) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > 900000 {
		return errors.New("identity store capacity exceeded")
	}
	current, err := s.Client.CoreV1().Secrets(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if current.ResourceVersion != version {
		return ErrConflict
	}
	if current.Data == nil {
		current.Data = map[string][]byte{}
	}
	current.Data["state.json"] = data
	_, err = s.Client.CoreV1().Secrets(s.Namespace).Update(ctx, current, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return ErrConflict
	}
	return err
}
func InitialSecret(namespace, name string) *core.Secret {
	data, _ := json.Marshal(Empty())
	return &core.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Data: map[string][]byte{"state.json": data}}
}

// MemoryStore is for isolated tests; production always uses SecretStore.
type MemoryStore struct {
	mu      sync.Mutex
	state   State
	version int
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{state: Empty()} }
func (s *MemoryStore) Read(ctx context.Context) (State, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, _ := json.Marshal(s.state)
	var copy State
	_ = json.Unmarshal(data, &copy)
	return copy, stringVersion(s.version), nil
}
func (s *MemoryStore) CompareAndSwap(ctx context.Context, state State, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stringVersion(s.version) != version {
		return ErrConflict
	}
	data, _ := json.Marshal(state)
	var next State
	_ = json.Unmarshal(data, &next)
	s.state = next
	s.version++
	return nil
}
