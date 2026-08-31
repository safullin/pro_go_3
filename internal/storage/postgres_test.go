package storage

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/safullin/pro_go_3/internal/domain"
)

func TestPostgresUsers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &PostgresStore{db: db}
	now := time.Now().UTC()
	mock.ExpectQuery("INSERT INTO users").WillReturnRows(sqlmock.NewRows([]string{"password_hash", "encryption_salt", "created_at"}).AddRow([]byte("hash"), []byte("salt"), now))
	user, err := store.CreateUser(context.Background(), "alice", []byte("hash"), []byte("salt"))
	if err != nil || user.ID == "" || user.Login != "alice" {
		t.Fatalf("create user: %+v %v", user, err)
	}
	mock.ExpectQuery("INSERT INTO users").WillReturnError(&pgconn.PgError{Code: "23505"})
	if _, err = store.CreateUser(context.Background(), "alice", nil, nil); !errors.Is(err, ErrLoginTaken) {
		t.Fatalf("expected duplicate login, got %v", err)
	}
	mock.ExpectQuery("SELECT id, login").WithArgs("alice").WillReturnRows(sqlmock.NewRows([]string{"id", "login", "password_hash", "encryption_salt", "created_at"}).AddRow(user.ID, "alice", []byte("hash"), []byte("salt"), now))
	found, err := store.UserByLogin(context.Background(), "alice")
	if err != nil || found.ID != user.ID {
		t.Fatalf("find user: %+v %v", found, err)
	}
	mock.ExpectQuery("SELECT id, login").WithArgs("missing").WillReturnError(sql.ErrNoRows)
	if _, err = store.UserByLogin(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing user, got %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSecrets(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &PostgresStore{db: db}
	ctx := context.Background()
	userID := uuid.NewString()
	id := uuid.NewString()
	now := time.Now().UTC()
	secret := domain.Secret{ID: id, Kind: domain.SecretKindText, Ciphertext: []byte("cipher"), Nonce: []byte("nonce")}
	mock.ExpectQuery("INSERT INTO secrets").WithArgs(id, userID, domain.SecretKindText, secret.Ciphertext, secret.Nonce, int64(0)).WillReturnRows(sqlmock.NewRows([]string{"version", "is_deleted", "updated_at"}).AddRow(int64(1), false, now))
	created, err := store.PutSecret(ctx, userID, secret, 0)
	if err != nil || created.Version != 1 {
		t.Fatalf("put secret: %+v %v", created, err)
	}
	mock.ExpectQuery("INSERT INTO secrets").WillReturnError(sql.ErrNoRows)
	if _, err = store.PutSecret(ctx, userID, secret, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected put conflict, got %v", err)
	}
	mock.ExpectQuery("SELECT id, user_id").WithArgs(id, userID).WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "kind", "ciphertext", "nonce", "version", "is_deleted", "updated_at"}).AddRow(id, userID, int16(domain.SecretKindText), []byte("cipher"), []byte("nonce"), int64(1), false, now))
	loaded, err := store.GetSecret(ctx, userID, id)
	if err != nil || loaded.ID != id {
		t.Fatalf("get secret: %+v %v", loaded, err)
	}
	mock.ExpectQuery("SELECT id, user_id").WithArgs(uuid.Nil.String(), userID).WillReturnError(sql.ErrNoRows)
	if _, err = store.GetSecret(ctx, userID, uuid.Nil.String()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected missing secret, got %v", err)
	}
	mock.ExpectQuery("SELECT id, user_id").WithArgs(userID, int64(0)).WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "kind", "ciphertext", "nonce", "version", "is_deleted", "updated_at"}).AddRow(id, userID, int16(domain.SecretKindText), []byte("cipher"), []byte("nonce"), int64(1), false, now))
	listed, cursor, err := store.ListSecrets(ctx, userID, 0)
	if err != nil || len(listed) != 1 || cursor != 1 {
		t.Fatalf("list secrets: %+v %d %v", listed, cursor, err)
	}
	mock.ExpectExec("UPDATE secrets SET").WithArgs(id, userID, int64(1)).WillReturnResult(sqlmock.NewResult(0, 1))
	if err = store.DeleteSecret(ctx, userID, id, 1); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("UPDATE secrets SET").WithArgs(id, userID, int64(2)).WillReturnResult(sqlmock.NewResult(0, 0))
	if err = store.DeleteSecret(ctx, userID, id, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected delete conflict, got %v", err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresPingAndClose(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	store := &PostgresStore{db: db}
	mock.ExpectPing()
	if err = store.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	mock.ExpectClose()
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
}
