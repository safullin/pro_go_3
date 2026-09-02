package client

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/safullin/pro_go_3/internal/auth"
	"github.com/safullin/pro_go_3/internal/config"
	"github.com/safullin/pro_go_3/internal/domain"
	"github.com/safullin/pro_go_3/internal/server"
	"github.com/safullin/pro_go_3/internal/storage"
	"github.com/safullin/pro_go_3/internal/testcert"
)

func TestClientWorkflowAndCache(t *testing.T) {
	api, closeServer := newClientTestServer(t)
	defer closeServer()
	ctx := context.Background()
	if _, err := api.Put(ctx, "", domain.SecretKindText, domain.Payload{}, 0); err == nil {
		t.Fatal("unauthenticated put succeeded")
	}
	session, err := api.Register(ctx, "alice", "strong-password", "bufnet")
	if err != nil || session.Token == "" || session.Address != "bufnet" {
		t.Fatalf("register failed: %+v %v", session, err)
	}
	entry, err := api.Put(ctx, "", domain.SecretKindCredentials, domain.Payload{
		Name: "example.com", Metadata: "personal", Credentials: &domain.Credentials{Login: "alice", Password: "secret"},
	}, 0)
	if err != nil || entry.Secret.ID == "" || entry.Secret.Version == 0 || entry.Secret.Name != "example.com" {
		t.Fatalf("put failed: %+v %v", entry, err)
	}
	loaded, err := api.Get(ctx, entry.Secret.ID)
	if err != nil || loaded.Payload.Credentials.Password != "secret" {
		t.Fatalf("get failed: %+v %v", loaded, err)
	}
	search, err := api.Search(ctx, "personal")
	if err != nil || len(search) != 1 || search[0].Secret.ID != entry.Secret.ID {
		t.Fatalf("search failed: %+v %v", search, err)
	}
	if _, err = api.Search(ctx, " "); err == nil {
		t.Fatal("empty search accepted")
	}
	cachePath := filepath.Join(t.TempDir(), "cache.json")
	initial, err := api.SyncToCache(ctx, 0, cachePath)
	if err != nil || len(initial.Entries) != 1 || initial.Cursor != entry.Secret.Version {
		t.Fatalf("initial sync failed: %+v %v", initial, err)
	}
	cacheData, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cacheData, []byte("example.com")) || bytes.Contains(cacheData, []byte("secret")) {
		t.Fatal("local cache contains plaintext")
	}
	offline := NewOffline()
	if err = offline.Restore(session, "strong-password"); err != nil {
		t.Fatal(err)
	}
	cached, err := offline.ReadCache(cachePath)
	if err != nil || len(cached.Entries) != 1 || cached.Entries[0].Payload.Name != "example.com" {
		t.Fatalf("offline cache failed: %+v %v", cached, err)
	}
	if _, err = offline.GetCached(cachePath, entry.Secret.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = offline.GetCached(cachePath, "missing"); err != ErrCacheMiss {
		t.Fatalf("expected cache miss, got %v", err)
	}
	cachedSearch, err := offline.SearchCached(cachePath, "EXAMPLE")
	if err != nil || len(cachedSearch) != 1 {
		t.Fatalf("cached search failed: %+v %v", cachedSearch, err)
	}
	if _, err = offline.SearchCached(cachePath, " "); err == nil {
		t.Fatal("empty cached search accepted")
	}
	loaded.Payload.Credentials.Password = "changed"
	updated, err := api.Put(ctx, entry.Secret.ID, domain.SecretKindCredentials, loaded.Payload, entry.Secret.Version)
	if err != nil || updated.Secret.Version <= entry.Secret.Version {
		t.Fatalf("update failed: %+v %v", updated, err)
	}
	if _, err = api.Put(ctx, entry.Secret.ID, domain.SecretKindCredentials, loaded.Payload, entry.Secret.Version); err == nil {
		t.Fatal("stale update succeeded")
	}
	if err = api.Delete(ctx, entry.Secret.ID, updated.Secret.Version); err != nil {
		t.Fatal(err)
	}
	changes, err := api.SyncToCache(ctx, updated.Secret.Version, cachePath)
	if err != nil || len(changes.Deleted) != 1 || changes.Deleted[0] != entry.Secret.ID {
		t.Fatalf("delete sync failed: %+v %v", changes, err)
	}
	cached, err = offline.ReadCache(cachePath)
	if err != nil || len(cached.Entries) != 0 {
		t.Fatalf("deleted cache entry remained: %+v %v", cached, err)
	}
	if _, err = api.Get(ctx, entry.Secret.ID); err == nil {
		t.Fatal("deleted entry returned")
	}
	second := &Client{rpc: api.rpc}
	if _, err = second.Login(ctx, "alice", "wrong-password", "bufnet"); err == nil {
		t.Fatal("wrong password login succeeded")
	}
	if _, err = second.Login(ctx, "alice", "strong-password", "bufnet"); err != nil {
		t.Fatal(err)
	}
}

func TestSessionFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "nested", "session.json")
	session := Session{Token: "token", Login: "alice", Salt: []byte("1234567890123456"), Address: "server", UpdatedAt: time.Now()}
	if err := SaveSession(path, session); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSession(path)
	if err != nil || loaded.Token != session.Token || loaded.Login != session.Login {
		t.Fatalf("unexpected session: %+v %v", loaded, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("session permissions are too broad: %v %v", info.Mode(), err)
	}
	if err = SaveSession("", session); err == nil {
		t.Fatal("empty session path accepted")
	}
	if _, err = LoadSession(filepath.Join(directory, "missing")); err == nil {
		t.Fatal("missing session loaded")
	}
	invalid := filepath.Join(directory, "invalid.json")
	if err = os.WriteFile(invalid, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadSession(invalid); err == nil {
		t.Fatal("invalid session loaded")
	}
	if _, err = DefaultSessionPath(); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreDialAndCacheValidation(t *testing.T) {
	api := NewOffline()
	if err := api.Restore(Session{}, "password"); err == nil {
		t.Fatal("invalid session restored")
	}
	if err := api.Restore(Session{Token: "token", Login: "alice", Salt: []byte("short")}, "password"); err == nil {
		t.Fatal("invalid salt restored")
	}
	if err := api.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(config.Client{Address: "localhost:1", CAFile: "missing.pem"}); err == nil {
		t.Fatal("missing CA accepted")
	}
	invalidCA := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(invalidCA, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(config.Client{Address: "localhost:1", CAFile: invalidCA}); err == nil {
		t.Fatal("invalid CA accepted")
	}
	bundle, err := testcert.Generate()
	if err != nil {
		t.Fatal(err)
	}
	validCA := filepath.Join(t.TempDir(), "valid-ca.pem")
	if err = os.WriteFile(validCA, bundle.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	connection, err := Dial(config.Client{Address: "localhost:1", CAFile: validCA, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = api.ReadCache(""); err == nil {
		t.Fatal("empty cache path accepted")
	}
	if !IsUnavailable(status.Error(codes.Unavailable, "down")) || !IsUnavailable(context.DeadlineExceeded) || IsUnavailable(status.Error(codes.PermissionDenied, "denied")) {
		t.Fatal("unexpected unavailable classification")
	}
}

func newClientTestServer(t *testing.T) (*Client, func()) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	manager, err := auth.NewManager(strings.Repeat("s", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := testcert.Generate()
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := server.NewGRPCServer(server.NewService(storage.NewMemory(), manager), manager, bundle.ServerCredentials())
	go func() { _ = grpcServer.Serve(listener) }()
	clientCredentials, err := bundle.ClientCredentials()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(clientCredentials),
	)
	if err != nil {
		t.Fatal(err)
	}
	api := New(connection)
	return api, func() {
		_ = connection.Close()
		grpcServer.Stop()
		_ = listener.Close()
	}
}
