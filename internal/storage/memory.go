package storage

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/safullin/pro_go_3/internal/domain"
)

// MemoryStore is a concurrency-safe store intended for tests and local use.
type MemoryStore struct {
	mu      sync.RWMutex
	users   map[string]User
	logins  map[string]string
	secrets map[string]domain.Secret
	version int64
	closed  bool
}

// NewMemory creates an empty in-memory store.
func NewMemory() *MemoryStore {
	return &MemoryStore{
		users:   make(map[string]User),
		logins:  make(map[string]string),
		secrets: make(map[string]domain.Secret),
	}
}

// CreateUser registers a user with a unique login.
func (s *MemoryStore) CreateUser(_ context.Context, login string, passwordHash, salt []byte) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.logins[login]; exists {
		return User{}, ErrLoginTaken
	}
	user := User{
		ID:           uuid.NewString(),
		Login:        login,
		PasswordHash: append([]byte(nil), passwordHash...),
		Salt:         append([]byte(nil), salt...),
		CreatedAt:    time.Now().UTC(),
	}
	s.users[user.ID] = user
	s.logins[login] = user.ID
	return cloneUser(user), nil
}

// UserByLogin returns authentication data for a login.
func (s *MemoryStore) UserByLogin(_ context.Context, login string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, exists := s.logins[login]
	if !exists {
		return User{}, ErrNotFound
	}
	return cloneUser(s.users[id]), nil
}

// PutSecret creates or updates an encrypted secret with optimistic locking.
func (s *MemoryStore) PutSecret(_ context.Context, userID string, secret domain.Secret, expectedVersion int64) (domain.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.secrets[secret.ID]
	if exists {
		if current.UserID != userID {
			return domain.Secret{}, ErrNotFound
		}
		if expectedVersion == 0 || current.Version != expectedVersion {
			return domain.Secret{}, ErrConflict
		}
	} else if expectedVersion != 0 {
		return domain.Secret{}, ErrConflict
	}
	s.version++
	secret.UserID = userID
	secret.Version = s.version
	secret.Deleted = false
	secret.UpdatedAt = time.Now().UTC()
	s.secrets[secret.ID] = cloneSecret(secret)
	return cloneSecret(secret), nil
}

// GetSecret returns an encrypted secret owned by a user.
func (s *MemoryStore) GetSecret(_ context.Context, userID, id string) (domain.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	secret, exists := s.secrets[id]
	if !exists || secret.UserID != userID || secret.Deleted {
		return domain.Secret{}, ErrNotFound
	}
	return cloneSecret(secret), nil
}

// ListSecrets returns changes newer than the supplied cursor.
func (s *MemoryStore) ListSecrets(_ context.Context, userID string, sinceVersion int64) ([]domain.Secret, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domain.Secret, 0)
	cursor := sinceVersion
	for _, secret := range s.secrets {
		if secret.UserID != userID || secret.Version <= sinceVersion {
			continue
		}
		result = append(result, cloneSecret(secret))
		if secret.Version > cursor {
			cursor = secret.Version
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	return result, cursor, nil
}

// DeleteSecret marks a secret as deleted with optimistic locking.
func (s *MemoryStore) DeleteSecret(_ context.Context, userID, id string, expectedVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secret, exists := s.secrets[id]
	if !exists || secret.UserID != userID || secret.Deleted {
		return ErrNotFound
	}
	if expectedVersion == 0 || secret.Version != expectedVersion {
		return ErrConflict
	}
	s.version++
	secret.Version = s.version
	secret.Deleted = true
	secret.Ciphertext = nil
	secret.Nonce = nil
	secret.UpdatedAt = time.Now().UTC()
	s.secrets[id] = secret
	return nil
}

// Ping checks that the in-memory store has not been closed.
func (s *MemoryStore) Ping(_ context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrNotFound
	}
	return nil
}

// Close marks the in-memory store as closed.
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func cloneUser(user User) User {
	user.PasswordHash = append([]byte(nil), user.PasswordHash...)
	user.Salt = append([]byte(nil), user.Salt...)
	return user
}

func cloneSecret(secret domain.Secret) domain.Secret {
	secret.Ciphertext = append([]byte(nil), secret.Ciphertext...)
	secret.Nonce = append([]byte(nil), secret.Nonce...)
	return secret
}
