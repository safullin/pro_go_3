package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/safullin/pro_go_3/internal/domain"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	user, err := store.CreateUser(ctx, "alice", []byte("hash"), []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	user.PasswordHash[0] = 'x'
	found, err := store.UserByLogin(ctx, "alice")
	if err != nil || string(found.PasswordHash) != "hash" {
		t.Fatalf("unexpected user: %+v %v", found, err)
	}
	if _, err = store.CreateUser(ctx, "alice", nil, nil); !errors.Is(err, ErrLoginTaken) {
		t.Fatalf("expected duplicate login, got %v", err)
	}
	if _, err = store.UserByLogin(ctx, "unknown"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected unknown user, got %v", err)
	}
	secret := domain.Secret{ID: uuid.NewString(), Kind: domain.SecretKindText, Name: "Note", Metadata: "personal", Ciphertext: []byte("cipher"), Nonce: []byte("nonce")}
	created, err := store.PutSecret(ctx, found.ID, secret, 0)
	if err != nil || created.Version == 0 {
		t.Fatalf("create secret: %+v %v", created, err)
	}
	created.Ciphertext[0] = 'x'
	loaded, err := store.GetSecret(ctx, found.ID, secret.ID)
	if err != nil || string(loaded.Ciphertext) != "cipher" {
		t.Fatalf("get secret: %+v %v", loaded, err)
	}
	if _, err = store.PutSecret(ctx, found.ID, secret, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected create conflict, got %v", err)
	}
	if _, err = store.PutSecret(ctx, found.ID, secret, loaded.Version+1); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected update conflict, got %v", err)
	}
	other, _ := store.CreateUser(ctx, "bob", []byte("hash"), []byte("salt"))
	if _, err = store.GetSecret(ctx, other.ID, secret.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other user read secret: %v", err)
	}
	if _, err = store.PutSecret(ctx, other.ID, secret, loaded.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other user updated secret: %v", err)
	}
	secret.Ciphertext = []byte("changed")
	updated, err := store.PutSecret(ctx, found.ID, secret, loaded.Version)
	if err != nil || updated.Version <= loaded.Version {
		t.Fatalf("update secret: %+v %v", updated, err)
	}
	changes, cursor, err := store.ListSecrets(ctx, found.ID, 0)
	if err != nil || len(changes) != 1 || cursor != updated.Version {
		t.Fatalf("list secrets: %d %d %v", len(changes), cursor, err)
	}
	changes, _, _ = store.ListSecrets(ctx, found.ID, cursor)
	if len(changes) != 0 {
		t.Fatal("old changes returned")
	}
	matches, err := store.SearchSecrets(ctx, found.ID, "PERSON")
	if err != nil || len(matches) != 1 || matches[0].ID != secret.ID {
		t.Fatalf("search secret: %+v %v", matches, err)
	}
	matches, err = store.SearchSecrets(ctx, other.ID, "personal")
	if err != nil || len(matches) != 0 {
		t.Fatalf("other user search returned secrets: %+v %v", matches, err)
	}
	if err = store.DeleteSecret(ctx, found.ID, secret.ID, updated.Version+1); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected delete conflict, got %v", err)
	}
	if err = store.DeleteSecret(ctx, other.ID, secret.ID, updated.Version); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other user deleted secret: %v", err)
	}
	if err = store.DeleteSecret(ctx, found.ID, secret.ID, updated.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = store.GetSecret(ctx, found.ID, secret.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted secret returned: %v", err)
	}
	changes, _, _ = store.ListSecrets(ctx, found.ID, updated.Version)
	if len(changes) != 1 || !changes[0].Deleted || changes[0].Name != "" || changes[0].Metadata != "" {
		t.Fatalf("delete tombstone missing: %+v", changes)
	}
	matches, err = store.SearchSecrets(ctx, found.ID, "personal")
	if err != nil || len(matches) != 0 {
		t.Fatalf("deleted secret found: %+v %v", matches, err)
	}
	if err = store.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = store.Ping(ctx); err == nil {
		t.Fatal("closed store accepted ping")
	}
}
