//go:build integration

package storage

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/safullin/pro_go_3/internal/domain"
)

func TestPostgresMetadataMigration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URI")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URI is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "metadata_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, dropErr := admin.Exec(cleanupCtx, "DROP SCHEMA "+quotedSchema+" CASCADE"); dropErr != nil {
			t.Errorf("remove test schema: %v", dropErr)
		}
	}()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, migration := range []string{initialMigration, metadataMigration} {
		if _, err = pool.Exec(ctx, migration); err != nil {
			t.Fatal(err)
		}
	}
	store := &PostgresStore{pool: pool}
	user, err := store.CreateUser(ctx, "alice", []byte("hash"), []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := store.PutSecret(ctx, user.ID, domain.Secret{
		ID: uuid.NewString(), Kind: domain.SecretKindText, Ciphertext: []byte("legacy encrypted data"), Nonce: make([]byte, 12),
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	oversized, err := store.PutSecret(ctx, user.ID, domain.Secret{
		ID: uuid.NewString(), Kind: domain.SecretKindText, Name: strings.Repeat("n", domain.MaxSecretNameLength+1), Ciphertext: []byte("encrypted"), Nonce: make([]byte, 12),
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, metadataLimitsMigration)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "22001" {
		t.Fatalf("oversized metadata did not block migration: %v", err)
	}
	unchanged, err := store.GetSecret(ctx, user.ID, oversized.ID)
	if err != nil || unchanged.Name != oversized.Name {
		t.Fatalf("failed migration changed data: %+v %v", unchanged, err)
	}
	oversized.Name = "Note"
	if _, err = store.PutSecret(ctx, user.ID, oversized, oversized.Version); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = pool.Exec(ctx, metadataLimitsMigration); err != nil {
			t.Fatal(err)
		}
	}
	pool.Reset()
	for column, length := range map[string]int{"name": domain.MaxSecretNameLength, "metadata": domain.MaxSecretMetadataLength} {
		var actualLength int
		if err = pool.QueryRow(ctx, `SELECT character_maximum_length FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'secrets' AND column_name = $2`, schema, column).Scan(&actualLength); err != nil || actualLength != length {
			t.Fatalf("unexpected %s limit: %d %v", column, actualLength, err)
		}
	}
	loaded, err := store.GetSecret(ctx, user.ID, legacy.ID)
	if err != nil || loaded.Name != "" || string(loaded.Ciphertext) != string(legacy.Ciphertext) || loaded.Version != legacy.Version {
		t.Fatalf("migration changed legacy secret: %+v %v", loaded, err)
	}
	valid := domain.Secret{
		ID: uuid.NewString(), Kind: domain.SecretKindText,
		Name: strings.Repeat("\u0438", domain.MaxSecretNameLength), Metadata: strings.Repeat("\u044f", domain.MaxSecretMetadataLength),
		Ciphertext: []byte("encrypted"), Nonce: make([]byte, 12),
	}
	if _, err = store.PutSecret(ctx, user.ID, valid, 0); err != nil {
		t.Fatalf("unicode metadata at limits rejected: %v", err)
	}
	for _, column := range []string{"name", "metadata"} {
		invalid := valid
		invalid.ID = uuid.NewString()
		if column == "name" {
			invalid.Name += "x"
		} else {
			invalid.Metadata += "x"
		}
		_, err = store.PutSecret(ctx, user.ID, invalid, 0)
		if !errors.As(err, &pgErr) || pgErr.Code != "22001" {
			t.Fatalf("database accepted oversized %s: %v", column, err)
		}
	}
}
