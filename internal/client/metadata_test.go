package client

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/safullin/pro_go_3/internal/domain"
	"github.com/safullin/pro_go_3/internal/vaultcrypto"
)

func TestLegacySecretOnlineAndOffline(t *testing.T) {
	api, store, closeServer := newClientTestServer(t)
	t.Cleanup(closeServer)
	ctx := context.Background()
	session, err := api.Register(ctx, "legacy-user", "strong-password", "bufnet")
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.UserByLogin(ctx, session.Login)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	payload := domain.Payload{Name: "Old note", Metadata: "personal", Text: &domain.TextData{Value: "private text"}}
	ciphertext, nonce, err := vaultcrypto.Encrypt(api.key, id, domain.SecretKindText, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.PutSecret(ctx, user.ID, domain.Secret{ID: id, Kind: domain.SecretKindText, Ciphertext: ciphertext, Nonce: nonce}, 0)
	if err != nil {
		t.Fatal(err)
	}
	assertEntry := func(entry domain.Entry) {
		t.Helper()
		if entry.Secret.Name != payload.Name || entry.Secret.Metadata != payload.Metadata || entry.Payload.Text == nil || entry.Payload.Text.Value != payload.Text.Value {
			t.Fatalf("legacy data was not restored: %+v", entry)
		}
	}
	entry, err := api.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	assertEntry(entry)
	cachePath := filepath.Join(t.TempDir(), "cache.json")
	result, err := api.SyncToCache(ctx, 0, cachePath)
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("sync legacy secret: %+v %v", result, err)
	}
	assertEntry(result.Entries[0])
	offline := &Client{token: api.token, key: api.key}
	result, err = offline.ReadCache(cachePath)
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("read legacy cache: %+v %v", result, err)
	}
	assertEntry(result.Entries[0])
	entry, err = offline.GetCached(cachePath, id)
	if err != nil {
		t.Fatal(err)
	}
	assertEntry(entry)
	for _, query := range []string{"old note", "personal"} {
		entries, searchErr := offline.SearchCached(cachePath, query)
		if searchErr != nil || len(entries) != 1 {
			t.Fatalf("search legacy cache for %q: %+v %v", query, entries, searchErr)
		}
		assertEntry(entries[0])
	}
}

func TestDecryptMetadataIntegrity(t *testing.T) {
	api := &Client{key: make([]byte, 32)}
	payload := domain.Payload{Name: "Note", Metadata: "personal", Text: &domain.TextData{Value: "secret"}}
	ciphertext, nonce, err := vaultcrypto.Encrypt(api.key, "id", domain.SecretKindText, payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, storedName, metadata string
		corrupt, wantError         bool
	}{
		{name: "legacy"},
		{name: "matching", storedName: "Note", metadata: "personal"},
		{name: "changed name", storedName: "Other", metadata: "personal", wantError: true},
		{name: "changed metadata", storedName: "Note", metadata: "other", wantError: true},
		{name: "missing metadata", storedName: "Note", wantError: true},
		{name: "corrupt legacy ciphertext", corrupt: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			secret := domain.Secret{ID: "id", Kind: domain.SecretKindText, Name: test.storedName, Metadata: test.metadata, Ciphertext: append([]byte(nil), ciphertext...), Nonce: nonce}
			if test.corrupt {
				secret.Ciphertext[0] ^= 1
			}
			_, decryptErr := api.decrypt(&secret)
			if (decryptErr != nil) != test.wantError {
				t.Fatalf("unexpected integrity result: %v", decryptErr)
			}
			if !test.wantError && (secret.Name != payload.Name || secret.Metadata != payload.Metadata) {
				t.Fatalf("metadata was not restored: %+v", secret)
			}
		})
	}
}

func TestMetadataLimitsDoNotPreventLegacyReads(t *testing.T) {
	api := &Client{token: "token", key: make([]byte, 32)}
	for _, payload := range []domain.Payload{
		{Name: strings.Repeat("n", domain.MaxSecretNameLength+1), Text: &domain.TextData{Value: "old text"}},
		{Name: "Note", Metadata: strings.Repeat("m", domain.MaxSecretMetadataLength+1), Text: &domain.TextData{Value: "old text"}},
	} {
		ciphertext, nonce, err := vaultcrypto.Encrypt(api.key, "id", domain.SecretKindText, payload)
		if err != nil {
			t.Fatal(err)
		}
		secret := domain.Secret{ID: "id", Kind: domain.SecretKindText, Ciphertext: ciphertext, Nonce: nonce}
		if _, err = api.decrypt(&secret); err != nil {
			t.Fatalf("legacy read rejected: %v", err)
		}
		if _, err = api.Put(context.Background(), "id", domain.SecretKindText, payload, 1); err == nil {
			t.Fatal("oversized metadata accepted for writing")
		}
	}
}
