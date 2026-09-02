package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"

	"github.com/safullin/pro_go_3/internal/domain"
)

func TestPostgresUsers(t *testing.T) {
	pool, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := &PostgresStore{pool: pool}
	now := time.Now().UTC()
	pool.ExpectQuery("INSERT INTO users").WithArgs(pgxmock.AnyArg(), "alice", []byte("hash"), []byte("salt")).
		WillReturnRows(pgxmock.NewRows([]string{"password_hash", "encryption_salt", "created_at"}).AddRow([]byte("hash"), []byte("salt"), now))
	user, err := store.CreateUser(context.Background(), "alice", []byte("hash"), []byte("salt"))
	if err != nil || user.ID == "" || user.Login != "alice" {
		t.Fatalf("create user: %+v %v", user, err)
	}
	pool.ExpectQuery("INSERT INTO users").WithArgs(pgxmock.AnyArg(), "alice", pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnError(&pgconn.PgError{Code: "23505"})
	if _, err = store.CreateUser(context.Background(), "alice", nil, nil); !errors.Is(err, ErrLoginTaken) {
		t.Fatalf("expected duplicate login, got %v", err)
	}
	pool.ExpectQuery("SELECT id, login").WithArgs("alice").
		WillReturnRows(pgxmock.NewRows([]string{"id", "login", "password_hash", "encryption_salt", "created_at"}).
			AddRow(user.ID, "alice", []byte("hash"), []byte("salt"), now))
	found, err := store.UserByLogin(context.Background(), "alice")
	if err != nil || found.ID != user.ID {
		t.Fatalf("find user: %+v %v", found, err)
	}
	pool.ExpectQuery("SELECT id, login").WithArgs("missing").WillReturnError(pgx.ErrNoRows)
	if _, err = store.UserByLogin(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing user, got %v", err)
	}
	if err = pool.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSecrets(t *testing.T) {
	pool, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := &PostgresStore{pool: pool}
	ctx := context.Background()
	userID := uuid.NewString()
	id := uuid.NewString()
	now := time.Now().UTC()
	secret := domain.Secret{
		ID: id, Kind: domain.SecretKindText, Name: "Note", Metadata: "personal",
		Ciphertext: []byte("cipher"), Nonce: []byte("nonce"),
	}
	pool.ExpectQuery("INSERT INTO secrets").
		WithArgs(id, userID, domain.SecretKindText, "Note", "personal", secret.Ciphertext, secret.Nonce, int64(0)).
		WillReturnRows(pgxmock.NewRows([]string{"version", "is_deleted", "updated_at"}).AddRow(int64(1), false, now))
	created, err := store.PutSecret(ctx, userID, secret, 0)
	if err != nil || created.Version != 1 {
		t.Fatalf("put secret: %+v %v", created, err)
	}
	pool.ExpectQuery("INSERT INTO secrets").
		WithArgs(id, userID, domain.SecretKindText, "Note", "personal", secret.Ciphertext, secret.Nonce, int64(0)).
		WillReturnError(pgx.ErrNoRows)
	if _, err = store.PutSecret(ctx, userID, secret, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected put conflict, got %v", err)
	}
	columns := []string{"id", "user_id", "kind", "name", "metadata", "ciphertext", "nonce", "version", "is_deleted", "updated_at"}
	pool.ExpectQuery("SELECT id, user_id").WithArgs(id, userID).
		WillReturnRows(pgxmock.NewRows(columns).AddRow(id, userID, int16(domain.SecretKindText), "Note", "personal", []byte("cipher"), []byte("nonce"), int64(1), false, now))
	loaded, err := store.GetSecret(ctx, userID, id)
	if err != nil || loaded.ID != id || loaded.Name != "Note" {
		t.Fatalf("get secret: %+v %v", loaded, err)
	}
	pool.ExpectQuery("SELECT id, user_id").WithArgs(uuid.Nil.String(), userID).WillReturnError(pgx.ErrNoRows)
	if _, err = store.GetSecret(ctx, userID, uuid.Nil.String()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing secret, got %v", err)
	}
	pool.ExpectQuery("FROM secrets WHERE user_id").WithArgs(userID, int64(0)).
		WillReturnRows(pgxmock.NewRows(columns).AddRow(id, userID, int16(domain.SecretKindText), "Note", "personal", []byte("cipher"), []byte("nonce"), int64(1), false, now))
	listed, cursor, err := store.ListSecrets(ctx, userID, 0)
	if err != nil || len(listed) != 1 || cursor != 1 {
		t.Fatalf("list secrets: %+v %d %v", listed, cursor, err)
	}
	pool.ExpectQuery("FROM secrets").WithArgs(userID, "person").
		WillReturnRows(pgxmock.NewRows(columns).AddRow(id, userID, int16(domain.SecretKindText), "Note", "personal", []byte("cipher"), []byte("nonce"), int64(1), false, now))
	found, err := store.SearchSecrets(ctx, userID, "person")
	if err != nil || len(found) != 1 || found[0].ID != id {
		t.Fatalf("search secrets: %+v %v", found, err)
	}
	pool.ExpectExec("UPDATE secrets SET").WithArgs(id, userID, int64(1)).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	if err = store.DeleteSecret(ctx, userID, id, 1); err != nil {
		t.Fatal(err)
	}
	pool.ExpectExec("UPDATE secrets SET").WithArgs(id, userID, int64(2)).WillReturnResult(pgxmock.NewResult("UPDATE", 0))
	if err = store.DeleteSecret(ctx, userID, id, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected delete conflict, got %v", err)
	}
	if err = pool.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresPingAndClose(t *testing.T) {
	pool, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	store := &PostgresStore{pool: pool}
	pool.ExpectPing()
	if err = store.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	pool.ExpectClose()
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = pool.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
