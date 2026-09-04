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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/safullin/pro_go_3/internal/auth"
	"github.com/safullin/pro_go_3/internal/domain"
	gophkeeperpb "github.com/safullin/pro_go_3/internal/proto"
	"github.com/safullin/pro_go_3/internal/storage"
	"github.com/safullin/pro_go_3/internal/testcert"
)

func TestGophKeeperAPI(t *testing.T) {
	api, closeServer := newTestAPI(t)
	defer closeServer()
	ctx := context.Background()
	register, err := api.Register(ctx, registerRequest("alice", "strong-password"))
	if err != nil || register.GetToken() == "" || len(register.GetSalt()) != 16 {
		t.Fatalf("register failed: %+v %v", register, err)
	}
	if _, err = api.Register(ctx, registerRequest("alice", "strong-password")); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected duplicate login, got %v", err)
	}
	if _, err = api.Register(ctx, registerRequest("x", "short")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid registration, got %v", err)
	}
	if _, err = api.Login(ctx, loginRequest("missing", "strong-password")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unknown login was accepted: %v", err)
	}
	if _, err = api.Login(ctx, loginRequest("alice", "wrong-password")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected invalid login, got %v", err)
	}
	login, err := api.Login(ctx, loginRequest("alice", "strong-password"))
	if err != nil || login.GetToken() == "" {
		t.Fatalf("login failed: %+v %v", login, err)
	}
	if _, err = api.ListSecrets(ctx, listRequest(0)); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthorized list succeeded: %v", err)
	}
	if _, err = api.ListSecrets(bearerContext(ctx, "bad-token"), listRequest(0)); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid token succeeded: %v", err)
	}
	if _, err = api.ListSecrets(metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Basic value")), listRequest(0)); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid authorization scheme succeeded: %v", err)
	}
	authorized := bearerContext(ctx, login.GetToken())
	if _, err = api.ListSecrets(authorized, listRequest(-1)); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("negative cursor accepted: %v", err)
	}
	id := uuid.NewString()
	request := putRequest(id, "Mail", "personal example.com", []byte("encrypted"), 0)
	created, err := api.PutSecret(authorized, request)
	if err != nil || created.GetVersion() == 0 || created.GetUpdatedAt() == nil {
		t.Fatalf("create secret failed: %+v %v", created, err)
	}
	invalidSecrets := []*gophkeeperpb.Secret{
		nil,
		secretMessage("bad", "name", []byte("x"), make([]byte, 12), gophkeeperpb.SecretKind_SECRET_KIND_TEXT),
		secretMessage(uuid.NewString(), "name", []byte("x"), make([]byte, 12), gophkeeperpb.SecretKind_SECRET_KIND_UNSPECIFIED),
		secretMessage(uuid.NewString(), "name", nil, make([]byte, 12), gophkeeperpb.SecretKind_SECRET_KIND_TEXT),
		secretMessage(uuid.NewString(), "name", []byte("x"), []byte("bad"), gophkeeperpb.SecretKind_SECRET_KIND_TEXT),
		secretMessage(uuid.NewString(), "", []byte("x"), make([]byte, 12), gophkeeperpb.SecretKind_SECRET_KIND_TEXT),
	}
	for _, secret := range invalidSecrets {
		invalid := gophkeeperpb.PutSecretRequest_builder{Secret: secret}.Build()
		if _, putErr := api.PutSecret(authorized, invalid); status.Code(putErr) != codes.InvalidArgument {
			t.Fatalf("invalid secret accepted: %+v %v", secret, putErr)
		}
	}
	request.SetExpectedVersion(0)
	if _, err = api.PutSecret(authorized, request); status.Code(err) != codes.Aborted {
		t.Fatalf("create conflict not detected: %v", err)
	}
	request.SetExpectedVersion(created.GetVersion())
	request.GetSecret().SetCiphertext([]byte("updated"))
	updated, err := api.PutSecret(authorized, request)
	if err != nil || updated.GetVersion() <= created.GetVersion() {
		t.Fatalf("update secret failed: %+v %v", updated, err)
	}
	loaded, err := api.GetSecret(authorized, getRequest(id))
	if err != nil || string(loaded.GetCiphertext()) != "updated" || loaded.GetName() != "Mail" {
		t.Fatalf("get secret failed: %+v %v", loaded, err)
	}
	if _, err = api.GetSecret(authorized, getRequest("bad")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid id accepted: %v", err)
	}
	if _, err = api.GetSecret(authorized, getRequest(uuid.NewString())); status.Code(err) != codes.NotFound {
		t.Fatalf("missing secret returned: %v", err)
	}
	listed, err := api.ListSecrets(authorized, listRequest(0))
	if err != nil || len(listed.GetSecrets()) != 1 || listed.GetCursor() != updated.GetVersion() {
		t.Fatalf("list failed: %+v %v", listed, err)
	}
	search, err := api.SearchSecrets(authorized, gophkeeperpb.SearchSecretsRequest_builder{Query: "example"}.Build())
	if err != nil || len(search.GetSecrets()) != 1 || search.GetSecrets()[0].GetId() != id {
		t.Fatalf("search failed: %+v %v", search, err)
	}
	if _, err = api.SearchSecrets(authorized, gophkeeperpb.SearchSecretsRequest_builder{}.Build()); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty search accepted: %v", err)
	}
	if _, err = api.DeleteSecret(authorized, deleteRequest("bad", updated.GetVersion())); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid delete id accepted: %v", err)
	}
	if _, err = api.DeleteSecret(authorized, deleteRequest(id, updated.GetVersion()+1)); status.Code(err) != codes.Aborted {
		t.Fatalf("delete conflict not detected: %v", err)
	}
	if _, err = api.DeleteSecret(authorized, deleteRequest(id, updated.GetVersion())); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, err = api.GetSecret(authorized, getRequest(id)); status.Code(err) != codes.NotFound {
		t.Fatalf("deleted secret returned: %v", err)
	}
	changes, err := api.ListSecrets(authorized, listRequest(updated.GetVersion()))
	if err != nil || len(changes.GetSecrets()) != 1 || !changes.GetSecrets()[0].GetDeleted() {
		t.Fatalf("delete was not synchronized: %+v %v", changes, err)
	}
}

func TestServiceRequiresIdentity(t *testing.T) {
	manager, _ := auth.NewManager(strings.Repeat("s", 32), time.Hour)
	service := NewService(storage.NewMemory(), manager)
	ctx := context.Background()
	checks := []func() error{
		func() error { _, err := service.GetSecret(ctx, getRequest("")); return err },
		func() error {
			_, err := service.PutSecret(ctx, gophkeeperpb.PutSecretRequest_builder{}.Build())
			return err
		},
		func() error { _, err := service.ListSecrets(ctx, listRequest(0)); return err },
		func() error {
			_, err := service.SearchSecrets(ctx, gophkeeperpb.SearchSecretsRequest_builder{}.Build())
			return err
		},
		func() error { _, err := service.DeleteSecret(ctx, deleteRequest("", 0)); return err },
	}
	for _, check := range checks {
		if err := check(); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("direct call without identity succeeded: %v", err)
		}
	}
}

func TestPutSecretMetadataLimits(t *testing.T) {
	service := &Service{store: storage.NewMemory()}
	ctx := context.WithValue(context.Background(), identityKey{}, auth.Identity{UserID: uuid.NewString()})
	for _, test := range []struct {
		name, secretName, metadata string
		wantCode                   codes.Code
	}{
		{name: "at limits", secretName: strings.Repeat("\u0438", domain.MaxSecretNameLength), metadata: strings.Repeat("\u044f", domain.MaxSecretMetadataLength), wantCode: codes.OK},
		{name: "long name", secretName: strings.Repeat("\u0438", domain.MaxSecretNameLength+1), wantCode: codes.InvalidArgument},
		{name: "long metadata", secretName: "Note", metadata: strings.Repeat("\u044f", domain.MaxSecretMetadataLength+1), wantCode: codes.InvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := putRequest(uuid.NewString(), test.secretName, test.metadata, []byte("encrypted"), 0)
			_, err := service.PutSecret(ctx, request)
			if status.Code(err) != test.wantCode {
				t.Fatalf("unexpected status: %v", err)
			}
		})
	}
}

func newTestAPI(t *testing.T) (gophkeeperpb.GophKeeperClient, func()) {
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
	grpcServer := NewGRPCServer(NewService(storage.NewMemory(), manager), manager, bundle.ServerCredentials())
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
	return gophkeeperpb.NewGophKeeperClient(connection), func() {
		_ = connection.Close()
		grpcServer.Stop()
		_ = listener.Close()
	}
}

func registerRequest(login, password string) *gophkeeperpb.RegisterRequest {
	return gophkeeperpb.RegisterRequest_builder{Login: login, Password: password}.Build()
}

func loginRequest(login, password string) *gophkeeperpb.LoginRequest {
	return gophkeeperpb.LoginRequest_builder{Login: login, Password: password}.Build()
}

func listRequest(since int64) *gophkeeperpb.ListSecretsRequest {
	return gophkeeperpb.ListSecretsRequest_builder{SinceVersion: since}.Build()
}

func getRequest(id string) *gophkeeperpb.GetSecretRequest {
	return gophkeeperpb.GetSecretRequest_builder{Id: id}.Build()
}

func deleteRequest(id string, version int64) *gophkeeperpb.DeleteSecretRequest {
	return gophkeeperpb.DeleteSecretRequest_builder{Id: id, ExpectedVersion: version}.Build()
}

func putRequest(id, name, metadataValue string, ciphertext []byte, version int64) *gophkeeperpb.PutSecretRequest {
	secret := secretMessage(id, name, ciphertext, make([]byte, 12), gophkeeperpb.SecretKind_SECRET_KIND_TEXT)
	secret.SetMetadata(metadataValue)
	return gophkeeperpb.PutSecretRequest_builder{Secret: secret, ExpectedVersion: version}.Build()
}

func secretMessage(id, name string, ciphertext, nonce []byte, kind gophkeeperpb.SecretKind) *gophkeeperpb.Secret {
	return gophkeeperpb.Secret_builder{Id: id, Name: name, Kind: kind, Ciphertext: ciphertext, Nonce: nonce}.Build()
}

func bearerContext(ctx context.Context, token string) context.Context {
	return metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
}
