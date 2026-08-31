package client

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/safullin/pro_go_3/internal/auth"
	"github.com/safullin/pro_go_3/internal/config"
	"github.com/safullin/pro_go_3/internal/domain"
	"github.com/safullin/pro_go_3/internal/server"
	"github.com/safullin/pro_go_3/internal/storage"
)

func TestClientWorkflow(t *testing.T) {
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
		Name: "example.com", Credentials: &domain.Credentials{Login: "alice", Password: "secret"},
	}, 0)
	if err != nil || entry.Secret.ID == "" || entry.Secret.Version == 0 {
		t.Fatalf("put failed: %+v %v", entry, err)
	}
	loaded, err := api.Get(ctx, entry.Secret.ID)
	if err != nil || loaded.Payload.Credentials.Password != "secret" {
		t.Fatalf("get failed: %+v %v", loaded, err)
	}
	initial, err := api.Sync(ctx, 0)
	if err != nil || len(initial.Entries) != 1 || initial.Cursor != entry.Secret.Version {
		t.Fatalf("initial sync failed: %+v %v", initial, err)
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
	changes, err := api.Sync(ctx, updated.Secret.Version)
	if err != nil || len(changes.Deleted) != 1 || changes.Deleted[0] != entry.Secret.ID {
		t.Fatalf("delete sync failed: %+v %v", changes, err)
	}
	if _, err = api.Get(ctx, entry.Secret.ID); err == nil {
		t.Fatal("deleted entry returned")
	}
	second, closeSecond := newClientOnSameConnection(t, api)
	defer closeSecond()
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

func TestRestoreAndDialValidation(t *testing.T) {
	api := &Client{}
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
	connection, err := Dial(config.Client{Address: "localhost:1", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
}

func newClientTestServer(t *testing.T) (*Client, func()) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	manager, err := auth.NewManager(strings.Repeat("s", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := server.NewGRPCServer(server.NewService(storage.NewMemory(), manager), manager)
	go func() { _ = grpcServer.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
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

func newClientOnSameConnection(t *testing.T, source *Client) (*Client, func()) {
	t.Helper()
	return &Client{rpc: source.rpc}, func() {}
}
