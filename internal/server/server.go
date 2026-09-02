package server

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/safullin/pro_go_3/internal/auth"
	"github.com/safullin/pro_go_3/internal/domain"
	gophkeeperpb "github.com/safullin/pro_go_3/internal/proto"
	"github.com/safullin/pro_go_3/internal/storage"
	"github.com/safullin/pro_go_3/internal/vaultcrypto"
)

const maxSecretSize = 16 << 20

var dummyPasswordHash = []byte("$2a$10$P8T8Pq5ev7u8kpsyKBifCugAdzaUhr2EkuxFHwPFfcclXj5.RfTmm")

type identityKey struct{}

// Service implements authentication and encrypted secret synchronization.
type Service struct {
	gophkeeperpb.UnimplementedGophKeeperServer
	store  storage.Store
	tokens *auth.Manager
}

// NewService creates a GophKeeper service.
func NewService(store storage.Store, tokens *auth.Manager) *Service {
	return &Service{store: store, tokens: tokens}
}

// NewGRPCServer creates a gRPC server with mandatory TLS transport credentials.
func NewGRPCServer(service *Service, tokens *auth.Manager, transport credentials.TransportCredentials) *grpc.Server {
	options := []grpc.ServerOption{
		grpc.Creds(transport),
		grpc.UnaryInterceptor(AuthorizationInterceptor(tokens)),
		grpc.MaxRecvMsgSize(maxSecretSize + 1024),
	}
	server := grpc.NewServer(options...)
	gophkeeperpb.RegisterGophKeeperServer(server, service)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(server, healthServer)
	return server
}

// AuthorizationInterceptor validates bearer tokens for protected methods.
func AuthorizationInterceptor(tokens *auth.Manager) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod == gophkeeperpb.GophKeeper_Register_FullMethodName || info.FullMethod == gophkeeperpb.GophKeeper_Login_FullMethodName {
			return handler(ctx, request)
		}
		identity, err := identityFromMetadata(ctx, tokens)
		if err != nil {
			return nil, err
		}
		return handler(context.WithValue(ctx, identityKey{}, identity), request)
	}
}

// Register creates a user and immediately authenticates the new account.
func (s *Service) Register(ctx context.Context, request *gophkeeperpb.RegisterRequest) (*gophkeeperpb.AuthResponse, error) {
	login := strings.TrimSpace(request.GetLogin())
	if len(login) < 3 || len(login) > 128 {
		return nil, status.Error(codes.InvalidArgument, "login must contain from 3 to 128 characters")
	}
	hash, err := auth.HashPassword(request.GetPassword())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid password: %v", err)
	}
	salt, err := vaultcrypto.GenerateSalt()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate encryption salt: %v", err)
	}
	user, err := s.store.CreateUser(ctx, login, hash, salt)
	if errors.Is(err, storage.ErrLoginTaken) {
		return nil, status.Error(codes.AlreadyExists, "login is already taken")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create user: %v", err)
	}
	return s.authResponse(user)
}

// Login authenticates an existing account.
func (s *Service) Login(ctx context.Context, request *gophkeeperpb.LoginRequest) (*gophkeeperpb.AuthResponse, error) {
	user, err := s.store.UserByLogin(ctx, strings.TrimSpace(request.GetLogin()))
	hash := dummyPasswordHash
	userExists := err == nil
	if userExists {
		hash = user.PasswordHash
	}
	passwordValid := auth.VerifyPassword(hash, request.GetPassword())
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, status.Errorf(codes.Internal, "find user: %v", err)
	}
	if !userExists || !passwordValid {
		return nil, status.Error(codes.Unauthenticated, "invalid login or password")
	}
	return s.authResponse(user)
}

// PutSecret creates or updates an encrypted secret.
func (s *Service) PutSecret(ctx context.Context, request *gophkeeperpb.PutSecretRequest) (*gophkeeperpb.Secret, error) {
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, err
	}
	secret, err := secretFromProto(request.GetSecret())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid secret: %v", err)
	}
	secret, err = s.store.PutSecret(ctx, identity.UserID, secret, request.GetExpectedVersion())
	if errors.Is(err, storage.ErrConflict) {
		return nil, status.Error(codes.Aborted, "secret was changed by another client")
	}
	if errors.Is(err, storage.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "save secret: %v", err)
	}
	return secretToProto(secret), nil
}

// GetSecret returns an encrypted secret owned by the authenticated user.
func (s *Service) GetSecret(ctx context.Context, request *gophkeeperpb.GetSecretRequest) (*gophkeeperpb.Secret, error) {
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = uuid.Parse(request.GetId()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid secret id")
	}
	secret, err := s.store.GetSecret(ctx, identity.UserID, request.GetId())
	if errors.Is(err, storage.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get secret: %v", err)
	}
	return secretToProto(secret), nil
}

// ListSecrets returns encrypted changes after a synchronization cursor.
func (s *Service) ListSecrets(ctx context.Context, request *gophkeeperpb.ListSecretsRequest) (*gophkeeperpb.ListSecretsResponse, error) {
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if request.GetSinceVersion() < 0 {
		return nil, status.Error(codes.InvalidArgument, "synchronization cursor cannot be negative")
	}
	secrets, cursor, err := s.store.ListSecrets(ctx, identity.UserID, request.GetSinceVersion())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list secrets: %v", err)
	}
	items := make([]*gophkeeperpb.Secret, 0, len(secrets))
	for _, secret := range secrets {
		items = append(items, secretToProto(secret))
	}
	return gophkeeperpb.ListSecretsResponse_builder{Cursor: cursor, Secrets: items}.Build(), nil
}

// SearchSecrets returns active encrypted secrets matching name or metadata.
func (s *Service) SearchSecrets(ctx context.Context, request *gophkeeperpb.SearchSecretsRequest) (*gophkeeperpb.SearchSecretsResponse, error) {
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, err
	}
	query := strings.TrimSpace(request.GetQuery())
	if query == "" || len(query) > 1024 {
		return nil, status.Error(codes.InvalidArgument, "search query must contain from 1 to 1024 characters")
	}
	secrets, err := s.store.SearchSecrets(ctx, identity.UserID, query)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "search secrets: %v", err)
	}
	items := make([]*gophkeeperpb.Secret, 0, len(secrets))
	for _, secret := range secrets {
		items = append(items, secretToProto(secret))
	}
	return gophkeeperpb.SearchSecretsResponse_builder{Secrets: items}.Build(), nil
}

// DeleteSecret marks a secret as deleted for synchronization with other clients.
func (s *Service) DeleteSecret(ctx context.Context, request *gophkeeperpb.DeleteSecretRequest) (*gophkeeperpb.DeleteSecretResponse, error) {
	identity, err := identityFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = uuid.Parse(request.GetId()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid secret id")
	}
	err = s.store.DeleteSecret(ctx, identity.UserID, request.GetId(), request.GetExpectedVersion())
	if errors.Is(err, storage.ErrConflict) {
		return nil, status.Error(codes.Aborted, "secret was changed by another client")
	}
	if errors.Is(err, storage.ErrNotFound) {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "delete secret: %v", err)
	}
	return gophkeeperpb.DeleteSecretResponse_builder{}.Build(), nil
}

func (s *Service) authResponse(user storage.User) (*gophkeeperpb.AuthResponse, error) {
	token, err := s.tokens.Issue(auth.Identity{UserID: user.ID, Login: user.Login})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "issue authorization token: %v", err)
	}
	return gophkeeperpb.AuthResponse_builder{Token: token, Salt: append([]byte(nil), user.Salt...)}.Build(), nil
}

func identityFromMetadata(ctx context.Context, tokens *auth.Manager) (auth.Identity, error) {
	values := metadata.ValueFromIncomingContext(ctx, "authorization")
	if len(values) != 1 {
		return auth.Identity{}, status.Error(codes.Unauthenticated, "authorization token is required")
	}
	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return auth.Identity{}, status.Error(codes.Unauthenticated, "invalid authorization header")
	}
	identity, err := tokens.Parse(token)
	if err != nil {
		return auth.Identity{}, status.Error(codes.Unauthenticated, "invalid authorization token")
	}
	return identity, nil
}

func identityFromContext(ctx context.Context) (auth.Identity, error) {
	identity, ok := ctx.Value(identityKey{}).(auth.Identity)
	if !ok || identity.UserID == "" {
		return auth.Identity{}, status.Error(codes.Unauthenticated, "authorization token is required")
	}
	return identity, nil
}

func secretFromProto(secret *gophkeeperpb.Secret) (domain.Secret, error) {
	if secret == nil {
		return domain.Secret{}, errors.New("secret is required")
	}
	if _, err := uuid.Parse(secret.GetId()); err != nil {
		return domain.Secret{}, errors.New("invalid secret id")
	}
	kind := domain.SecretKind(secret.GetKind())
	if !kind.Valid() {
		return domain.Secret{}, errors.New("unsupported secret kind")
	}
	if len(secret.GetCiphertext()) == 0 || len(secret.GetCiphertext()) > maxSecretSize {
		return domain.Secret{}, errors.New("invalid encrypted payload size")
	}
	if len(secret.GetNonce()) != 12 {
		return domain.Secret{}, errors.New("invalid encryption nonce")
	}
	if strings.TrimSpace(secret.GetName()) == "" {
		return domain.Secret{}, errors.New("secret name is required")
	}
	return domain.Secret{
		ID:         secret.GetId(),
		Kind:       kind,
		Name:       secret.GetName(),
		Metadata:   secret.GetMetadata(),
		Ciphertext: append([]byte(nil), secret.GetCiphertext()...),
		Nonce:      append([]byte(nil), secret.GetNonce()...),
	}, nil
}

func secretToProto(secret domain.Secret) *gophkeeperpb.Secret {
	return gophkeeperpb.Secret_builder{
		Id:         secret.ID,
		Kind:       gophkeeperpb.SecretKind(secret.Kind),
		Name:       secret.Name,
		Metadata:   secret.Metadata,
		Ciphertext: append([]byte(nil), secret.Ciphertext...),
		Nonce:      append([]byte(nil), secret.Nonce...),
		Version:    secret.Version,
		Deleted:    secret.Deleted,
		UpdatedAt:  timestamppb.New(secret.UpdatedAt),
	}.Build()
}
