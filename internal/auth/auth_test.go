package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	hash, err := HashPassword("strong-password")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "strong-password") {
		t.Fatal("password was not verified")
	}
	if VerifyPassword(hash, "wrong-password") {
		t.Fatal("wrong password was verified")
	}
	if _, err = HashPassword("short"); err == nil {
		t.Fatal("short password was accepted")
	}
}

func TestManager(t *testing.T) {
	if _, err := NewManager("short", time.Hour); err == nil {
		t.Fatal("short signing secret was accepted")
	}
	if _, err := NewManager(strings.Repeat("a", 32), 0); err == nil {
		t.Fatal("invalid token lifetime was accepted")
	}
	manager, err := NewManager(strings.Repeat("a", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	manager.now = func() time.Time { return now }
	if _, err = manager.Issue(Identity{}); err == nil {
		t.Fatal("incomplete identity was accepted")
	}
	token, err := manager.Issue(Identity{UserID: "user-id", Login: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := manager.Parse(token)
	if err != nil || identity.UserID != "user-id" || identity.Login != "alice" {
		t.Fatalf("unexpected identity: %+v %v", identity, err)
	}
	for _, invalid := range []string{"", "bad", token + "x", "!" + token[1:]} {
		if _, parseErr := manager.Parse(invalid); !errors.Is(parseErr, ErrInvalidToken) {
			t.Fatalf("expected invalid token for %q, got %v", invalid, parseErr)
		}
	}
	manager.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err = manager.Parse(token); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected expired token, got %v", err)
	}
}
