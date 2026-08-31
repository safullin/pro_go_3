package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/safullin/pro_go_3/internal/domain"
)

//go:embed migrations/001_init.sql
var initialMigration string

// PostgresStore persists users and encrypted secrets in PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres opens a database connection and applies the schema migration.
func NewPostgres(ctx context.Context, dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	store := &PostgresStore{db: db}
	if err = store.Ping(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err = db.ExecContext(ctx, initialMigration); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply database migration: %w", err)
	}
	return store, nil
}

// CreateUser registers a user with a unique login.
func (s *PostgresStore) CreateUser(ctx context.Context, login string, passwordHash, salt []byte) (User, error) {
	user := User{ID: uuid.NewString(), Login: login}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO users (id, login, password_hash, encryption_salt)
		VALUES ($1, $2, $3, $4)
		RETURNING password_hash, encryption_salt, created_at`,
		user.ID, login, passwordHash, salt,
	).Scan(&user.PasswordHash, &user.Salt, &user.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return User{}, ErrLoginTaken
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

// UserByLogin returns authentication data for a login.
func (s *PostgresStore) UserByLogin(ctx context.Context, login string) (User, error) {
	var user User
	err := s.db.QueryRowContext(ctx, `
		SELECT id, login, password_hash, encryption_salt, created_at
		FROM users WHERE login = $1`, login,
	).Scan(&user.ID, &user.Login, &user.PasswordHash, &user.Salt, &user.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("find user: %w", err)
	}
	return user, nil
}

// PutSecret creates or updates an encrypted secret with optimistic locking.
func (s *PostgresStore) PutSecret(ctx context.Context, userID string, secret domain.Secret, expectedVersion int64) (domain.Secret, error) {
	secret.UserID = userID
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO secrets (id, user_id, kind, ciphertext, nonce, version, is_deleted, updated_at)
		VALUES ($1, $2, $3, $4, $5, nextval('secret_version_seq'), FALSE, NOW())
		ON CONFLICT (id) DO UPDATE SET
			kind = EXCLUDED.kind,
			ciphertext = EXCLUDED.ciphertext,
			nonce = EXCLUDED.nonce,
			version = nextval('secret_version_seq'),
			is_deleted = FALSE,
			updated_at = NOW()
		WHERE secrets.user_id = EXCLUDED.user_id
			AND secrets.version = $6
			AND $6 > 0
		RETURNING version, is_deleted, updated_at`,
		secret.ID, userID, secret.Kind, secret.Ciphertext, secret.Nonce, expectedVersion,
	).Scan(&secret.Version, &secret.Deleted, &secret.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Secret{}, ErrConflict
	}
	if err != nil {
		return domain.Secret{}, fmt.Errorf("put secret: %w", err)
	}
	return secret, nil
}

// GetSecret returns an encrypted secret owned by a user.
func (s *PostgresStore) GetSecret(ctx context.Context, userID, id string) (domain.Secret, error) {
	var secret domain.Secret
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, kind, ciphertext, nonce, version, is_deleted, updated_at
		FROM secrets WHERE id = $1 AND user_id = $2 AND is_deleted = FALSE`, id, userID,
	).Scan(&secret.ID, &secret.UserID, &secret.Kind, &secret.Ciphertext, &secret.Nonce, &secret.Version, &secret.Deleted, &secret.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Secret{}, ErrNotFound
	}
	if err != nil {
		return domain.Secret{}, fmt.Errorf("get secret: %w", err)
	}
	return secret, nil
}

// ListSecrets returns changes newer than the supplied cursor.
func (s *PostgresStore) ListSecrets(ctx context.Context, userID string, sinceVersion int64) ([]domain.Secret, int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, kind, ciphertext, nonce, version, is_deleted, updated_at
		FROM secrets WHERE user_id = $1 AND version > $2 ORDER BY version`, userID, sinceVersion)
	if err != nil {
		return nil, sinceVersion, fmt.Errorf("list secrets: %w", err)
	}
	defer rows.Close()
	secrets := make([]domain.Secret, 0)
	cursor := sinceVersion
	for rows.Next() {
		var secret domain.Secret
		if err = rows.Scan(&secret.ID, &secret.UserID, &secret.Kind, &secret.Ciphertext, &secret.Nonce, &secret.Version, &secret.Deleted, &secret.UpdatedAt); err != nil {
			return nil, cursor, fmt.Errorf("scan secret: %w", err)
		}
		secrets = append(secrets, secret)
		cursor = secret.Version
	}
	if err = rows.Err(); err != nil {
		return nil, cursor, fmt.Errorf("read secrets: %w", err)
	}
	return secrets, cursor, nil
}

// DeleteSecret marks a secret as deleted with optimistic locking.
func (s *PostgresStore) DeleteSecret(ctx context.Context, userID, id string, expectedVersion int64) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE secrets SET
			ciphertext = ''::bytea,
			nonce = ''::bytea,
			version = nextval('secret_version_seq'),
			is_deleted = TRUE,
			updated_at = NOW()
		WHERE id = $1 AND user_id = $2 AND version = $3 AND is_deleted = FALSE`,
		id, userID, expectedVersion)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count deleted secrets: %w", err)
	}
	if count == 0 {
		return ErrConflict
	}
	return nil
}

// Ping checks the database connection.
func (s *PostgresStore) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}

// Close closes the database connection pool.
func (s *PostgresStore) Close() error {
	return s.db.Close()
}
