package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseServer(t *testing.T) {
	cleanEnvironment(t, "RUN_ADDRESS", "DATABASE_URI", "AUTH_SECRET", "TLS_CERT", "TLS_KEY", "TOKEN_TTL")
	secret := strings.Repeat("s", 32)
	cfg, err := ParseServer([]string{"-a", "localhost:4000", "-d", "postgres://db", "-auth-secret", secret, "-tls-cert", "cert.pem", "-tls-key", "key.pem", "-token-ttl", "2h"})
	if err != nil || cfg.Address != "localhost:4000" || cfg.DatabaseURI != "postgres://db" || cfg.TokenLifetime != 2*time.Hour {
		t.Fatalf("unexpected server config: %+v %v", cfg, err)
	}
	t.Setenv("RUN_ADDRESS", "localhost:5000")
	t.Setenv("DATABASE_URI", "postgres://env")
	t.Setenv("AUTH_SECRET", strings.Repeat("e", 32))
	t.Setenv("TLS_CERT", "cert.pem")
	t.Setenv("TLS_KEY", "key.pem")
	t.Setenv("TOKEN_TTL", "3h")
	cfg, err = ParseServer(nil)
	if err != nil || cfg.Address != "localhost:5000" || cfg.TokenLifetime != 3*time.Hour || cfg.TLSKey != "key.pem" {
		t.Fatalf("environment was not applied: %+v %v", cfg, err)
	}
}

func TestParseServerErrors(t *testing.T) {
	cleanEnvironment(t, "RUN_ADDRESS", "DATABASE_URI", "AUTH_SECRET", "TLS_CERT", "TLS_KEY", "TOKEN_TTL")
	secret := strings.Repeat("s", 32)
	tests := [][]string{
		{},
		{"-d", "postgres://db", "-auth-secret", "short"},
		{"-d", "postgres://db", "-auth-secret", secret, "-tls-cert", "cert.pem"},
		{"-d", "postgres://db", "-auth-secret", secret, "-tls-cert", "cert.pem", "-tls-key", "key.pem", "-token-ttl", "0s"},
		{"-unknown"},
	}
	for _, args := range tests {
		if _, err := ParseServer(args); err == nil {
			t.Fatalf("invalid server config accepted: %v", args)
		}
	}
	t.Setenv("TOKEN_TTL", "bad")
	t.Setenv("DATABASE_URI", "postgres://db")
	t.Setenv("AUTH_SECRET", secret)
	if _, err := ParseServer(nil); err == nil {
		t.Fatal("invalid environment duration accepted")
	}
}

func TestParseClient(t *testing.T) {
	cleanEnvironment(t, "GOPHKEEPER_ADDRESS", "GOPHKEEPER_CA", "GOPHKEEPER_SERVER_NAME", "GOPHKEEPER_SESSION", "GOPHKEEPER_TIMEOUT")
	cfg, err := ParseClient([]string{"-a", "localhost:4000", "-ca", "ca.pem", "-timeout", "2s"})
	if err != nil || cfg.CAFile != "ca.pem" || cfg.Timeout != 2*time.Second {
		t.Fatalf("unexpected client config: %+v %v", cfg, err)
	}
	t.Setenv("GOPHKEEPER_ADDRESS", "localhost:5000")
	t.Setenv("GOPHKEEPER_CA", "ca.pem")
	t.Setenv("GOPHKEEPER_SERVER_NAME", "keeper.local")
	t.Setenv("GOPHKEEPER_SESSION", "session.json")
	t.Setenv("GOPHKEEPER_TIMEOUT", "3s")
	cfg, err = ParseClient(nil)
	if err != nil || cfg.Address != "localhost:5000" || cfg.CAFile != "ca.pem" || cfg.Timeout != 3*time.Second {
		t.Fatalf("environment was not applied: %+v %v", cfg, err)
	}
}

func TestParseClientErrors(t *testing.T) {
	cleanEnvironment(t, "GOPHKEEPER_ADDRESS", "GOPHKEEPER_CA", "GOPHKEEPER_SERVER_NAME", "GOPHKEEPER_SESSION", "GOPHKEEPER_TIMEOUT")
	for _, args := range [][]string{{}, {"-ca", "ca.pem", "-timeout", "0s"}, {"-unknown"}} {
		if _, err := ParseClient(args); err == nil {
			t.Fatalf("invalid client config accepted: %v", args)
		}
	}
	t.Setenv("GOPHKEEPER_CA", "ca.pem")
	t.Setenv("GOPHKEEPER_TIMEOUT", "bad")
	if _, err := ParseClient(nil); err == nil {
		t.Fatal("invalid duration environment accepted")
	}
}

func cleanEnvironment(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		value, exists := os.LookupEnv(name)
		_ = os.Unsetenv(name)
		originalName := name
		originalValue := value
		originalExists := exists
		t.Cleanup(func() {
			if originalExists {
				_ = os.Setenv(originalName, originalValue)
			} else {
				_ = os.Unsetenv(originalName)
			}
		})
	}
}
