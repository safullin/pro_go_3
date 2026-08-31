package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrInvalidToken indicates that a token is malformed or has an invalid signature.
	ErrInvalidToken = errors.New("invalid token")
	// ErrExpiredToken indicates that a token is no longer valid.
	ErrExpiredToken = errors.New("expired token")
)

// Identity identifies an authenticated user.
type Identity struct {
	UserID string
	Login  string
}

type claims struct {
	UserID    string `json:"sub"`
	Login     string `json:"login"`
	ExpiresAt int64  `json:"exp"`
}

// Manager issues and verifies HMAC-SHA256 authorization tokens.
type Manager struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewManager creates a token manager with the supplied signing secret and lifetime.
func NewManager(secret string, ttl time.Duration) (*Manager, error) {
	if len(secret) < 32 {
		return nil, errors.New("authorization secret must contain at least 32 characters")
	}
	if ttl <= 0 {
		return nil, errors.New("token lifetime must be positive")
	}
	return &Manager{secret: []byte(secret), ttl: ttl, now: time.Now}, nil
}

// Issue creates a signed token for an authenticated user.
func (m *Manager) Issue(identity Identity) (string, error) {
	if identity.UserID == "" || identity.Login == "" {
		return "", errors.New("user identity is incomplete")
	}
	payload, err := json.Marshal(claims{
		UserID:    identity.UserID,
		Login:     identity.Login,
		ExpiresAt: m.now().Add(m.ttl).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("marshal token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(m.sign(encoded)), nil
}

// Parse verifies a token and returns the represented identity.
func (m *Manager) Parse(token string) (Identity, error) {
	var identity Identity
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return identity, ErrInvalidToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, m.sign(parts[0])) {
		return identity, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return identity, ErrInvalidToken
	}
	var parsed claims
	if err = json.Unmarshal(payload, &parsed); err != nil || parsed.UserID == "" || parsed.Login == "" {
		return identity, ErrInvalidToken
	}
	if m.now().Unix() >= parsed.ExpiresAt {
		return identity, ErrExpiredToken
	}
	return Identity{UserID: parsed.UserID, Login: parsed.Login}, nil
}

func (m *Manager) sign(value string) []byte {
	hash := hmac.New(sha256.New, m.secret)
	_, _ = hash.Write([]byte(value))
	return hash.Sum(nil)
}

// HashPassword creates a bcrypt hash suitable for persistent storage.
func HashPassword(password string) ([]byte, error) {
	if len(password) < 8 {
		return nil, errors.New("password must contain at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	return hash, nil
}

// VerifyPassword compares a password with a bcrypt hash.
func VerifyPassword(hash []byte, password string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}
