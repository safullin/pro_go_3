package server

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/safullin/pro_go_3/internal/auth"
	gophkeeperpb "github.com/safullin/pro_go_3/internal/proto"
	"github.com/safullin/pro_go_3/internal/storage"
)

func TestGophKeeperAPI(t *testing.T) {
	api, closeServer := newTestAPI(t)
	defer closeServer()
	ctx := context.Background()
	register, err := api.Register(ctx, &gophkeeperpb.RegisterRequest{Login: "alice", Password: "strong-password"})
	if err != nil || register.GetToken() == "" || len(register.GetSalt()) != 16 {
		t.Fatalf("register failed: %+v %v", register, err)
	}
	if _, err = api.Register(ctx, &gophkeeperpb.RegisterRequest{Login: "alice", Password: "strong-password"}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected duplicate login, got %v", err)
	}
	if _, err = api.Register(ctx, &gophkeeperpb.RegisterRequest{Login: "x", Password: "short"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid registration, got %v", err)
	}
	if _, err = api.Login(ctx, &gophkeeperpb.LoginRequest{Login: "alice", Password: "wrong-password"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected invalid login, got %v", err)
	}
	login, err := api.Login(ctx, &gophkeeperpb.LoginRequest{Login: "alice", Password: "strong-password"})
	if err != nil || login.GetToken() == "" {
		t.Fatalf("login failed: %+v %v", login, err)
	}
	if _, err = api.ListSecrets(ctx, &gophkeeperpb.ListSecretsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthorized list succeeded: %v", err)
	}
	authorized := bearerContext(ctx, login.GetToken())
	if _, err = api.ListSecrets(bearerContext(ctx, "bad-token"), &gophkeeperpb.ListSecretsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid token succeeded: %v", err)
	}
	if _, err = api.ListSecrets(metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Basic value")), &gophkeeperpb.ListSecretsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid authorization scheme succeeded: %v", err)
	}
	if _, err = api.ListSecrets(authorized, &gophkeeperpb.ListSecretsRequest{SinceVersion: -1}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("negative cursor accepted: %v", err)
	}
	id := uuid.NewString()
	request := &gophkeeperpb.PutSecretRequest{Secret: &gophkeeperpb.Secret{
		Id:         id,
		Kind:       gophkeeperpb.SecretKind_SECRET_KIND_TEXT,
		Ciphertext: []byte("encrypted"),
		Nonce:      make([]byte, 12),
	}}
	created, err := api.PutSecret(authorized, request)
	if err != nil || created.GetVersion() == 0 || created.GetUpdatedAt() == nil {
		t.Fatalf("create secret failed: %+v %v", created, err)
	}
	invalidRequests := []*gophkeeperpb.PutSecretRequest{
		{},
		{Secret: &gophkeeperpb.Secret{Id: "bad", Kind: gophkeeperpb.SecretKind_SECRET_KIND_TEXT, Ciphertext: []byte("x"), Nonce: make([]byte, 12)}},
		{Secret: &gophkeeperpb.Secret{Id: uuid.NewString(), Kind: gophkeeperpb.SecretKind_SECRET_KIND_UNSPECIFIED, Ciphertext: []byte("x"), Nonce: make([]byte, 12)}},
		{Secret: &gophkeeperpb.Secret{Id: uuid.NewString(), Kind: gophkeeperpb.SecretKind_SECRET_KIND_TEXT, Nonce: make([]byte, 12)}},
		{Secret: &gophkeeperpb.Secret{Id: uuid.NewString(), Kind: gophkeeperpb.SecretKind_SECRET_KIND_TEXT, Ciphertext: []byte("x"), Nonce: []byte("bad")}},
	}
	for _, invalid := range invalidRequests {
		if _, putErr := api.PutSecret(authorized, invalid); status.Code(putErr) != codes.InvalidArgument {
			t.Fatalf("invalid secret accepted: %+v %v", invalid, putErr)
		}
	}
	request.ExpectedVersion = 0
	if _, err = api.PutSecret(authorized, request); status.Code(err) != codes.Aborted {
		t.Fatalf("create conflict not detected: %v", err)
	}
	request.ExpectedVersion = created.GetVersion()
	request.Secret.Ciphertext = []byte("updated")
	updated, err := api.PutSecret(authorized, request)
	if err != nil || updated.GetVersion() <= created.GetVersion() {
		t.Fatalf("update secret failed: %+v %v", updated, err)
	}
	loaded, err := api.GetSecret(authorized, &gophkeeperpb.GetSecretRequest{Id: id})
	if err != nil || string(loaded.GetCiphertext()) != "updated" {
		t.Fatalf("get secret failed: %+v %v", loaded, err)
	}
	if _, err = api.GetSecret(authorized, &gophkeeperpb.GetSecretRequest{Id: "bad"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid id accepted: %v", err)
	}
	if _, err = api.GetSecret(authorized, &gophkeeperpb.GetSecretRequest{Id: uuid.NewString()}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing secret returned: %v", err)
	}
	listed, err := api.ListSecrets(authorized, &gophkeeperpb.ListSecretsRequest{})
	if err != nil || len(listed.GetSecrets()) != 1 || listed.GetCursor() != updated.GetVersion() {
		t.Fatalf("list failed: %+v %v", listed, err)
	}
	if _, err = api.DeleteSecret(authorized, &gophkeeperpb.DeleteSecretRequest{Id: "bad", ExpectedVersion: updated.GetVersion()}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid delete id accepted: %v", err)
	}
	if _, err = api.DeleteSecret(authorized, &gophkeeperpb.DeleteSecretRequest{Id: id, ExpectedVersion: updated.GetVersion() + 1}); status.Code(err) != codes.Aborted {
		t.Fatalf("delete conflict not detected: %v", err)
	}
	if _, err = api.DeleteSecret(authorized, &gophkeeperpb.DeleteSecretRequest{Id: id, ExpectedVersion: updated.GetVersion()}); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, err = api.GetSecret(authorized, &gophkeeperpb.GetSecretRequest{Id: id}); status.Code(err) != codes.NotFound {
		t.Fatalf("deleted secret returned: %v", err)
	}
	changes, err := api.ListSecrets(authorized, &gophkeeperpb.ListSecretsRequest{SinceVersion: updated.GetVersion()})
	if err != nil || len(changes.GetSecrets()) != 1 || !changes.GetSecrets()[0].GetDeleted() {
		t.Fatalf("delete was not synchronized: %+v %v", changes, err)
	}
}

func TestServiceRequiresIdentity(t *testing.T) {
	manager, _ := auth.NewManager(strings.Repeat("s", 32), time.Hour)
	service := NewService(storage.NewMemory(), manager)
	ctx := context.Background()
	if _, err := service.GetSecret(ctx, &gophkeeperpb.GetSecretRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("direct get without identity succeeded: %v", err)
	}
	if _, err := service.PutSecret(ctx, &gophkeeperpb.PutSecretRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("direct put without identity succeeded: %v", err)
	}
	if _, err := service.ListSecrets(ctx, &gophkeeperpb.ListSecretsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("direct list without identity succeeded: %v", err)
	}
	if _, err := service.DeleteSecret(ctx, &gophkeeperpb.DeleteSecretRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("direct delete without identity succeeded: %v", err)
	}
}

func newTestAPI(t *testing.T) (gophkeeperpb.GophKeeperClient, func()) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	manager, err := auth.NewManager(strings.Repeat("s", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := NewGRPCServer(NewService(storage.NewMemory(), manager), manager)
	go func() { _ = grpcServer.Serve(listener) }()
	connection, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return gophkeeperpb.NewGophKeeperClient(connection), func() {
		_ = connection.Close()
		grpcServer.Stop()
		_ = listener.Close()
	}
}

func bearerContext(ctx context.Context, token string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
}
