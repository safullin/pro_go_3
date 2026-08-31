package vaultcrypto

import (
	"bytes"
	"testing"

	"github.com/safullin/pro_go_3/internal/domain"
)

func TestEncryptDecrypt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil || len(salt) != saltSize {
		t.Fatalf("unexpected salt: %d %v", len(salt), err)
	}
	key, err := DeriveKey("strong-password", salt)
	if err != nil {
		t.Fatal(err)
	}
	payload := domain.Payload{
		Name:        "example.com",
		Metadata:    "personal",
		Credentials: &domain.Credentials{Login: "alice", Password: "secret"},
	}
	ciphertext, nonce, err := Encrypt(key, "record-id", domain.SecretKindCredentials, payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("secret")) {
		t.Fatal("ciphertext contains plaintext")
	}
	decoded, err := Decrypt(key, "record-id", domain.SecretKindCredentials, ciphertext, nonce)
	if err != nil || decoded.Credentials.Password != payload.Credentials.Password || decoded.Metadata != payload.Metadata {
		t.Fatalf("unexpected decrypted payload: %+v %v", decoded, err)
	}
	wrongKey := append([]byte(nil), key...)
	wrongKey[0] ^= 1
	if _, err = Decrypt(wrongKey, "record-id", domain.SecretKindCredentials, ciphertext, nonce); err == nil {
		t.Fatal("wrong key decrypted payload")
	}
	if _, err = Decrypt(key, "other-id", domain.SecretKindCredentials, ciphertext, nonce); err == nil {
		t.Fatal("wrong additional data decrypted payload")
	}
}

func TestCryptoValidation(t *testing.T) {
	if _, err := DeriveKey("", make([]byte, saltSize)); err == nil {
		t.Fatal("empty password was accepted")
	}
	if _, err := DeriveKey("password", []byte("short")); err == nil {
		t.Fatal("short salt was accepted")
	}
	if _, _, err := Encrypt([]byte("short"), "id", domain.SecretKindText, domain.Payload{Name: "x", Text: &domain.TextData{}}); err == nil {
		t.Fatal("short key was accepted")
	}
	key := make([]byte, keySize)
	if _, _, err := Encrypt(key, "id", domain.SecretKindText, domain.Payload{}); err == nil {
		t.Fatal("invalid payload was accepted")
	}
	if _, err := Decrypt(key, "id", domain.SecretKindText, []byte("data"), []byte("short")); err == nil {
		t.Fatal("short nonce was accepted")
	}
}
