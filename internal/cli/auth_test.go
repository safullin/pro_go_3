package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/safullin/pro_go_3/internal/client"
)

func TestLoadCredentialsDoesNotDeriveKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	session := client.Session{Token: "token", Login: "alice", Salt: []byte("short")}
	if err := client.SaveSession(path, session); err != nil {
		t.Fatal(err)
	}
	calls := 0
	app := &application{sessionFile: path, readPassword: func() (string, error) {
		calls++
		return "password", nil
	}}
	loaded, password, err := app.loadCredentials()
	if err != nil || loaded.Token != session.Token || password != "password" || calls != 1 {
		t.Fatalf("load credentials: %+v %q %d %v", loaded, password, calls, err)
	}
	readErr := errors.New("password input failed")
	app.readPassword = func() (string, error) { return "", readErr }
	if _, _, err = app.loadCredentials(); !errors.Is(err, readErr) {
		t.Fatalf("password error lost: %v", err)
	}
	app.sessionFile = filepath.Join(t.TempDir(), "missing.json")
	if _, _, err = app.loadCredentials(); err == nil {
		t.Fatal("missing session accepted")
	}
}

func TestAuthenticatedCommandsReuseRestoredClient(t *testing.T) {
	address, caFile, closeServer := startCLITestServer(t)
	t.Cleanup(closeServer)
	path := filepath.Join(t.TempDir(), "session.json")
	session := client.Session{Token: "token", Login: "alice", Salt: make([]byte, 16)}
	if err := client.SaveSession(path, session); err != nil {
		t.Fatal(err)
	}
	passwordReads := 0
	app := &application{
		address: address, caFile: caFile, timeout: time.Second, sessionFile: path,
		readPassword: func() (string, error) {
			passwordReads++
			return "password", nil
		},
	}
	command := &cobra.Command{}
	command.SetContext(context.Background())
	called := false
	if err := app.withAuthenticated(command, func(_ context.Context, api *client.Client) error {
		called = true
		_, err := api.GetCached(path+".cache", "missing")
		if !errors.Is(err, client.ErrCacheMiss) {
			t.Fatalf("client was not restored: %v", err)
		}
		return nil
	}); err != nil || !called || passwordReads != 1 {
		t.Fatalf("authenticated command: called=%v reads=%d err=%v", called, passwordReads, err)
	}
	for _, test := range []struct {
		name         string
		onlineError  error
		wantFallback bool
	}{
		{name: "online"},
		{name: "unavailable", onlineError: status.Error(codes.Unavailable, "offline"), wantFallback: true},
		{name: "unauthenticated", onlineError: status.Error(codes.Unauthenticated, "expired")},
	} {
		t.Run(test.name, func(t *testing.T) {
			passwordReads = 0
			var onlineClient *client.Client
			fallbackCalled := false
			err := app.withOnlineFallback(command,
				func(_ context.Context, api *client.Client) error {
					onlineClient = api
					return test.onlineError
				},
				func(api *client.Client) error {
					fallbackCalled = true
					if api != onlineClient {
						t.Fatal("offline fallback created another client")
					}
					return nil
				},
			)
			if fallbackCalled != test.wantFallback || passwordReads != 1 {
				t.Fatalf("fallback=%v password reads=%d", fallbackCalled, passwordReads)
			}
			if test.wantFallback && err != nil || !test.wantFallback && !errors.Is(err, test.onlineError) {
				t.Fatalf("unexpected command result: %v", err)
			}
		})
	}
}
