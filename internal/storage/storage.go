package storage

import (
	"context"
	"errors"
	"time"

	"github.com/safullin/pro_go_3/internal/domain"
)

var (
	// ErrNotFound indicates that a requested record does not exist.
	ErrNotFound = errors.New("record not found")
	// ErrLoginTaken indicates that a login already belongs to another user.
	ErrLoginTaken = errors.New("login is already taken")
	// ErrConflict indicates that a secret was changed by another client.
	ErrConflict = errors.New("secret version conflict")
)

// User contains authentication data persisted by the server.
type User struct {
	ID           string
	Login        string
	PasswordHash []byte
	Salt         []byte
	CreatedAt    time.Time
}

// Store defines all persistent operations required by the server.
type Store interface {
	CreateUser(context.Context, string, []byte, []byte) (User, error)
	UserByLogin(context.Context, string) (User, error)
	PutSecret(context.Context, string, domain.Secret, int64) (domain.Secret, error)
	GetSecret(context.Context, string, string) (domain.Secret, error)
	ListSecrets(context.Context, string, int64) ([]domain.Secret, int64, error)
	SearchSecrets(context.Context, string, string) ([]domain.Secret, error)
	DeleteSecret(context.Context, string, string, int64) error
	Ping(context.Context) error
	Close() error
}
