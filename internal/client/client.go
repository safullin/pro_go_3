package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/safullin/pro_go_3/internal/config"
	"github.com/safullin/pro_go_3/internal/domain"
	gophkeeperpb "github.com/safullin/pro_go_3/internal/proto"
	"github.com/safullin/pro_go_3/internal/vaultcrypto"
)

// Session contains authorization data that may be persisted by the CLI.
type Session struct {
	Token     string    `json:"token"`
	Login     string    `json:"login"`
	Salt      []byte    `json:"salt"`
	Address   string    `json:"address"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SyncResult contains decrypted changes and the next synchronization cursor.
type SyncResult struct {
	Entries []domain.Entry
	Deleted []string
	Cursor  int64
}

// Client encrypts private data before sending it to the GophKeeper server.
type Client struct {
	rpc   gophkeeperpb.GophKeeperClient
	conn  *grpc.ClientConn
	token string
	key   []byte
}

// New creates a client around an existing gRPC connection.
func New(connection grpc.ClientConnInterface) *Client {
	return &Client{rpc: gophkeeperpb.NewGophKeeperClient(connection)}
}

// Dial opens a configured gRPC connection.
func Dial(cfg config.Client) (*Client, error) {
	transport, err := transportCredentials(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(cfg.Address,
		grpc.WithTransportCredentials(transport),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize((16<<20)+1024)),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to server: %w", err)
	}
	return &Client{rpc: gophkeeperpb.NewGophKeeperClient(conn), conn: conn}, nil
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Register creates an account and initializes the local encryption key.
func (c *Client) Register(ctx context.Context, login, password, address string) (Session, error) {
	response, err := c.rpc.Register(ctx, &gophkeeperpb.RegisterRequest{Login: login, Password: password})
	if err != nil {
		return Session{}, err
	}
	return c.acceptAuth(response, login, password, address)
}

// Login authenticates an account and initializes the local encryption key.
func (c *Client) Login(ctx context.Context, login, password, address string) (Session, error) {
	response, err := c.rpc.Login(ctx, &gophkeeperpb.LoginRequest{Login: login, Password: password})
	if err != nil {
		return Session{}, err
	}
	return c.acceptAuth(response, login, password, address)
}

// Restore initializes authorization and encryption from a persisted session.
func (c *Client) Restore(session Session, password string) error {
	if session.Token == "" || session.Login == "" {
		return errors.New("invalid session")
	}
	key, err := vaultcrypto.DeriveKey(password, session.Salt)
	if err != nil {
		return err
	}
	c.token = session.Token
	c.key = key
	return nil
}

// Put creates or updates a private entry.
func (c *Client) Put(ctx context.Context, id string, kind domain.SecretKind, payload domain.Payload, expectedVersion int64) (domain.Entry, error) {
	if err := c.ready(); err != nil {
		return domain.Entry{}, err
	}
	if id == "" {
		id = uuid.NewString()
	}
	ciphertext, nonce, err := vaultcrypto.Encrypt(c.key, id, kind, payload)
	if err != nil {
		return domain.Entry{}, err
	}
	response, err := c.rpc.PutSecret(c.authorize(ctx), &gophkeeperpb.PutSecretRequest{
		Secret: &gophkeeperpb.Secret{
			Id:         id,
			Kind:       gophkeeperpb.SecretKind(kind),
			Ciphertext: ciphertext,
			Nonce:      nonce,
		},
		ExpectedVersion: expectedVersion,
	})
	if err != nil {
		return domain.Entry{}, err
	}
	return domain.Entry{Secret: secretFromProto(response), Payload: payload}, nil
}

// Get downloads and decrypts one private entry.
func (c *Client) Get(ctx context.Context, id string) (domain.Entry, error) {
	if err := c.ready(); err != nil {
		return domain.Entry{}, err
	}
	response, err := c.rpc.GetSecret(c.authorize(ctx), &gophkeeperpb.GetSecretRequest{Id: id})
	if err != nil {
		return domain.Entry{}, err
	}
	secret := secretFromProto(response)
	payload, err := vaultcrypto.Decrypt(c.key, secret.ID, secret.Kind, secret.Ciphertext, secret.Nonce)
	if err != nil {
		return domain.Entry{}, err
	}
	return domain.Entry{Secret: secret, Payload: payload}, nil
}

// Sync downloads and decrypts all changes after a cursor.
func (c *Client) Sync(ctx context.Context, sinceVersion int64) (SyncResult, error) {
	if err := c.ready(); err != nil {
		return SyncResult{}, err
	}
	response, err := c.rpc.ListSecrets(c.authorize(ctx), &gophkeeperpb.ListSecretsRequest{SinceVersion: sinceVersion})
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{
		Entries: make([]domain.Entry, 0, len(response.GetSecrets())),
		Deleted: make([]string, 0),
		Cursor:  response.GetCursor(),
	}
	for _, item := range response.GetSecrets() {
		secret := secretFromProto(item)
		if secret.Deleted {
			result.Deleted = append(result.Deleted, secret.ID)
			continue
		}
		payload, decryptErr := vaultcrypto.Decrypt(c.key, secret.ID, secret.Kind, secret.Ciphertext, secret.Nonce)
		if decryptErr != nil {
			return SyncResult{}, fmt.Errorf("decrypt secret %s: %w", secret.ID, decryptErr)
		}
		result.Entries = append(result.Entries, domain.Entry{Secret: secret, Payload: payload})
	}
	return result, nil
}

// Delete removes a private entry with optimistic locking.
func (c *Client) Delete(ctx context.Context, id string, expectedVersion int64) error {
	if err := c.ready(); err != nil {
		return err
	}
	_, err := c.rpc.DeleteSecret(c.authorize(ctx), &gophkeeperpb.DeleteSecretRequest{Id: id, ExpectedVersion: expectedVersion})
	return err
}

// SaveSession atomically stores a session in a file readable only by its owner.
func SaveSession(path string, session Session) error {
	if path == "" {
		return errors.New("session path is required")
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create session directory: %w", err)
	}
	temporary := path + ".tmp"
	if err = os.WriteFile(temporary, data, 0o600); err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	if err = os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("replace session: %w", err)
	}
	return nil
}

// LoadSession reads a persisted session.
func LoadSession(path string) (Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Session{}, fmt.Errorf("read session: %w", err)
	}
	var session Session
	if err = json.Unmarshal(data, &session); err != nil {
		return Session{}, fmt.Errorf("decode session: %w", err)
	}
	if session.Token == "" || session.Login == "" || len(session.Salt) == 0 {
		return Session{}, errors.New("invalid session")
	}
	return session, nil
}

// DefaultSessionPath returns the platform-specific user session path.
func DefaultSessionPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user config directory: %w", err)
	}
	return filepath.Join(directory, "gophkeeper", "session.json"), nil
}

func (c *Client) acceptAuth(response *gophkeeperpb.AuthResponse, login, password, address string) (Session, error) {
	key, err := vaultcrypto.DeriveKey(password, response.GetSalt())
	if err != nil {
		return Session{}, err
	}
	c.token = response.GetToken()
	c.key = key
	return Session{
		Token:     response.GetToken(),
		Login:     login,
		Salt:      append([]byte(nil), response.GetSalt()...),
		Address:   address,
		UpdatedAt: time.Now().UTC(),
	}, nil
}

func (c *Client) ready() error {
	if c.token == "" || len(c.key) == 0 {
		return errors.New("authentication is required")
	}
	return nil
}

func (c *Client) authorize(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
}

func secretFromProto(secret *gophkeeperpb.Secret) domain.Secret {
	updatedAt := time.Time{}
	if secret.GetUpdatedAt() != nil {
		updatedAt = secret.GetUpdatedAt().AsTime()
	}
	return domain.Secret{
		ID:         secret.GetId(),
		Kind:       domain.SecretKind(secret.GetKind()),
		Ciphertext: append([]byte(nil), secret.GetCiphertext()...),
		Nonce:      append([]byte(nil), secret.GetNonce()...),
		Version:    secret.GetVersion(),
		Deleted:    secret.GetDeleted(),
		UpdatedAt:  updatedAt,
	}
}

func transportCredentials(cfg config.Client) (credentials.TransportCredentials, error) {
	if cfg.Insecure {
		return insecure.NewCredentials(), nil
	}
	certificate, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate) {
		return nil, errors.New("CA certificate is invalid")
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: cfg.ServerName,
	}), nil
}
