package vaultcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/safullin/pro_go_3/internal/domain"
)

const (
	saltSize = 16
	keySize  = 32
)

// GenerateSalt creates a random salt for deriving a user's encryption key.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey creates a 256-bit key from a password and salt with Argon2id.
func DeriveKey(password string, salt []byte) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password is required")
	}
	if len(salt) < saltSize {
		return nil, errors.New("invalid salt")
	}
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, keySize), nil
}

// Encrypt serializes and encrypts a payload with AES-256-GCM.
func Encrypt(key []byte, id string, kind domain.SecretKind, payload domain.Payload) ([]byte, []byte, error) {
	if err := payload.Validate(kind); err != nil {
		return nil, nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, nil, err
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal payload: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	return aead.Seal(nil, nonce, plain, additionalData(id, kind)), nonce, nil
}

// Decrypt authenticates, decrypts and validates a private payload.
func Decrypt(key []byte, id string, kind domain.SecretKind, ciphertext, nonce []byte) (domain.Payload, error) {
	var payload domain.Payload
	aead, err := newAEAD(key)
	if err != nil {
		return payload, err
	}
	if len(nonce) != aead.NonceSize() {
		return payload, errors.New("invalid nonce")
	}
	plain, err := aead.Open(nil, nonce, ciphertext, additionalData(id, kind))
	if err != nil {
		return payload, errors.New("unable to decrypt secret")
	}
	if err = json.Unmarshal(plain, &payload); err != nil {
		return payload, fmt.Errorf("unmarshal payload: %w", err)
	}
	if err = payload.Validate(kind); err != nil {
		return payload, fmt.Errorf("validate payload: %w", err)
	}
	return payload, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, errors.New("invalid encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func additionalData(id string, kind domain.SecretKind) []byte {
	return []byte(fmt.Sprintf("%s:%d", id, kind))
}
