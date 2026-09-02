package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/safullin/pro_go_3/internal/domain"
	"github.com/safullin/pro_go_3/internal/vaultcrypto"
)

var (
	// ErrCacheMiss indicates that a secret is absent from the local snapshot.
	ErrCacheMiss = errors.New("secret is absent from local cache")
)

var cacheAdditionalData = []byte("gophkeeper-cache-v1")

type cacheEnvelope struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type cacheSnapshot struct {
	Cursor  int64                    `json:"cursor"`
	Secrets map[string]domain.Secret `json:"secrets"`
}

// SyncToCache downloads changes, updates the encrypted local snapshot and returns decrypted changes.
func (c *Client) SyncToCache(ctx context.Context, sinceVersion int64, path string) (SyncResult, error) {
	if err := c.ready(); err != nil {
		return SyncResult{}, err
	}
	secrets, cursor, err := c.listRaw(ctx, sinceVersion)
	if err != nil {
		return SyncResult{}, err
	}
	var snapshot cacheSnapshot
	if sinceVersion == 0 {
		snapshot = cacheSnapshot{Secrets: make(map[string]domain.Secret)}
	} else {
		snapshot, err = c.loadCache(path)
		if err != nil {
			return SyncResult{}, err
		}
	}
	for _, item := range secrets {
		secret := secretFromProto(item)
		if secret.Deleted {
			delete(snapshot.Secrets, secret.ID)
			continue
		}
		snapshot.Secrets[secret.ID] = secret
	}
	if cursor > snapshot.Cursor {
		snapshot.Cursor = cursor
	}
	if err = c.saveCache(path, snapshot); err != nil {
		return SyncResult{}, err
	}
	return c.decryptSecrets(secrets, cursor)
}

// ReadCache decrypts and returns the latest locally cached snapshot.
func (c *Client) ReadCache(path string) (SyncResult, error) {
	if err := c.ready(); err != nil {
		return SyncResult{}, err
	}
	snapshot, err := c.loadCache(path)
	if err != nil {
		return SyncResult{}, err
	}
	secrets := make([]domain.Secret, 0, len(snapshot.Secrets))
	for _, secret := range snapshot.Secrets {
		secrets = append(secrets, secret)
	}
	sort.Slice(secrets, func(i, j int) bool { return secrets[i].UpdatedAt.After(secrets[j].UpdatedAt) })
	return c.decryptDomainSecrets(secrets, snapshot.Cursor)
}

// GetCached decrypts one secret from the latest local snapshot.
func (c *Client) GetCached(path, id string) (domain.Entry, error) {
	if err := c.ready(); err != nil {
		return domain.Entry{}, err
	}
	snapshot, err := c.loadCache(path)
	if err != nil {
		return domain.Entry{}, err
	}
	secret, ok := snapshot.Secrets[id]
	if !ok {
		return domain.Entry{}, ErrCacheMiss
	}
	payload, err := c.decrypt(secret)
	if err != nil {
		return domain.Entry{}, err
	}
	return domain.Entry{Secret: secret, Payload: payload}, nil
}

// SearchCached finds entries by name or metadata in the encrypted local snapshot.
func (c *Client) SearchCached(path, query string) ([]domain.Entry, error) {
	result, err := c.ReadCache(path)
	if err != nil {
		return nil, err
	}
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil, errors.New("search query is required")
	}
	entries := make([]domain.Entry, 0)
	for _, entry := range result.Entries {
		if strings.Contains(strings.ToLower(entry.Secret.Name), query) || strings.Contains(strings.ToLower(entry.Secret.Metadata), query) {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// IsUnavailable reports whether an operation failed because the server could not be reached.
func IsUnavailable(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || status.Code(err) == codes.Unavailable || status.Code(err) == codes.DeadlineExceeded
}

func (c *Client) decryptDomainSecrets(secrets []domain.Secret, cursor int64) (SyncResult, error) {
	result := SyncResult{Entries: make([]domain.Entry, 0, len(secrets)), Deleted: make([]string, 0), Cursor: cursor}
	for _, secret := range secrets {
		payload, err := c.decrypt(secret)
		if err != nil {
			return SyncResult{}, fmt.Errorf("decrypt secret %s: %w", secret.ID, err)
		}
		result.Entries = append(result.Entries, domain.Entry{Secret: secret, Payload: payload})
	}
	return result, nil
}

func (c *Client) loadCache(path string) (cacheSnapshot, error) {
	if path == "" {
		return cacheSnapshot{}, errors.New("cache path is required")
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cacheSnapshot{Secrets: make(map[string]domain.Secret)}, nil
	}
	if err != nil {
		return cacheSnapshot{}, fmt.Errorf("read cache: %w", err)
	}
	var envelope cacheEnvelope
	if err = json.Unmarshal(data, &envelope); err != nil {
		return cacheSnapshot{}, fmt.Errorf("decode cache envelope: %w", err)
	}
	plaintext, err := vaultcrypto.DecryptBytes(c.key, envelope.Ciphertext, envelope.Nonce, cacheAdditionalData)
	if err != nil {
		return cacheSnapshot{}, fmt.Errorf("decrypt cache: %w", err)
	}
	var snapshot cacheSnapshot
	if err = json.Unmarshal(plaintext, &snapshot); err != nil {
		return cacheSnapshot{}, fmt.Errorf("decode cache: %w", err)
	}
	if snapshot.Secrets == nil {
		snapshot.Secrets = make(map[string]domain.Secret)
	}
	return snapshot, nil
}

func (c *Client) saveCache(path string, snapshot cacheSnapshot) error {
	plaintext, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode cache: %w", err)
	}
	ciphertext, nonce, err := vaultcrypto.EncryptBytes(c.key, plaintext, cacheAdditionalData)
	if err != nil {
		return fmt.Errorf("encrypt cache: %w", err)
	}
	data, err := json.Marshal(cacheEnvelope{Nonce: nonce, Ciphertext: ciphertext})
	if err != nil {
		return fmt.Errorf("encode cache envelope: %w", err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	temporary := path + ".tmp"
	if err = os.WriteFile(temporary, data, 0o600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	if err = os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("replace cache: %w", err)
	}
	return nil
}
