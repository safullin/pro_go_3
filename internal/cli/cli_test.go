package cli

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/safullin/pro_go_3/internal/auth"
	"github.com/safullin/pro_go_3/internal/server"
	"github.com/safullin/pro_go_3/internal/storage"
)

func TestCLIWorkflow(t *testing.T) {
	address, closeServer := startCLITestServer(t)
	defer closeServer()
	session := filepath.Join(t.TempDir(), "session.json")
	run := func(args ...string) (string, error) {
		return runCLI(address, session, "strong-password", args...)
	}
	output, err := run("register", "alice")
	if err != nil || !strings.Contains(output, "Account registered") {
		t.Fatalf("register failed: %q %v", output, err)
	}
	output, err = run("login", "alice")
	if err != nil || !strings.Contains(output, "Authenticated") {
		t.Fatalf("login failed: %q %v", output, err)
	}
	output, err = run("add", "credentials", "--name", "Mail", "--metadata", "personal", "--login", "alice", "--secret", "mail-password")
	if err != nil {
		t.Fatal(err)
	}
	id, version := parseSaved(t, output)
	output, err = run("list")
	if err != nil || !strings.Contains(output, id) || !strings.Contains(output, "Mail") {
		t.Fatalf("list failed: %q %v", output, err)
	}
	output, err = run("get", id)
	if err != nil || !strings.Contains(output, "mail-password") {
		t.Fatalf("get credentials failed: %q %v", output, err)
	}
	output, err = run("update", "credentials", id, strconv.FormatInt(version, 10), "--name", "Mail", "--login", "bob", "--secret", "new-password")
	if err != nil {
		t.Fatal(err)
	}
	_, version = parseSaved(t, output)
	if _, err = run("update", "credentials", id, "bad", "--name", "Mail", "--login", "bob", "--secret", "new-password"); err == nil {
		t.Fatal("invalid update version accepted")
	}
	textOutput, err := run("add", "text", "--name", "Note", "--text", "private text")
	if err != nil {
		t.Fatal(err)
	}
	textID, _ := parseSaved(t, textOutput)
	output, err = run("get", textID)
	if err != nil || !strings.Contains(output, "private text") {
		t.Fatalf("get text failed: %q %v", output, err)
	}
	cardOutput, err := run("add", "card", "--name", "Main card", "--number", "4111111111111111", "--holder", "ALICE", "--expiry", "01/30", "--cvv", "123")
	if err != nil {
		t.Fatal(err)
	}
	cardID, _ := parseSaved(t, cardOutput)
	output, err = run("get", cardID)
	if err != nil || !strings.Contains(output, "4111111111111111") {
		t.Fatalf("get card failed: %q %v", output, err)
	}
	binaryPath := filepath.Join(t.TempDir(), "source.bin")
	if err = os.WriteFile(binaryPath, []byte{0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	binaryOutput, err := run("add", "binary", "--name", "Archive", "--file", binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	binaryID, _ := parseSaved(t, binaryOutput)
	if _, err = run("get", binaryID); err == nil {
		t.Fatal("binary output path was not required")
	}
	destination := filepath.Join(t.TempDir(), "destination.bin")
	output, err = run("get", binaryID, "--output", destination)
	if err != nil || !strings.Contains(output, "Saved to") {
		t.Fatalf("get binary failed: %q %v", output, err)
	}
	data, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(data, []byte{0, 1, 2, 3}) {
		t.Fatalf("unexpected binary output: %v %v", data, err)
	}
	output, err = run("sync", "--since", "0")
	if err != nil || !strings.Contains(output, "Changes: 4") {
		t.Fatalf("sync failed: %q %v", output, err)
	}
	if _, err = run("sync", "--since", "-1"); err == nil {
		t.Fatal("negative sync cursor accepted")
	}
	output, err = run("delete", id, strconv.FormatInt(version, 10))
	if err != nil || !strings.Contains(output, "Deleted") {
		t.Fatalf("delete failed: %q %v", output, err)
	}
	if _, err = run("delete", id, "bad"); err == nil {
		t.Fatal("invalid delete version accepted")
	}
}

func TestCLIValidationAndVersion(t *testing.T) {
	output, err := runCLI("localhost:1", filepath.Join(t.TempDir(), "session.json"), "password", "version")
	if err != nil || !strings.Contains(output, "Build version: test") || !strings.Contains(output, "Build commit: abc") {
		t.Fatalf("version failed: %q %v", output, err)
	}
	app := &application{stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	if _, err = app.masterPassword(); err == nil {
		t.Fatal("missing non-interactive password accepted")
	}
	app.timeout = 0
	if _, err = app.connect(); err == nil {
		t.Fatal("invalid timeout accepted")
	}
	app.timeout = time.Second
	if _, err = app.connect(); err == nil {
		t.Fatal("missing CA accepted")
	}
	if buildValue("") != "N/A" || buildValue("v1") != "v1" {
		t.Fatal("unexpected build value")
	}
	if envString("UNKNOWN_GOPHKEEPER_TEST", "fallback") != "fallback" {
		t.Fatal("unexpected environment fallback")
	}
}

func runCLI(address, session, password string, args ...string) (string, error) {
	output := &bytes.Buffer{}
	app := &application{
		build:       BuildInfo{Version: "test", Date: "today", Commit: "abc"},
		address:     address,
		insecure:    true,
		timeout:     5 * time.Second,
		sessionFile: session,
		password:    password,
		stdin:       strings.NewReader(""),
		stdout:      output,
		stderr:      output,
	}
	root := newRoot(app)
	root.SetArgs(args)
	err := root.Execute()
	return output.String(), err
}

func parseSaved(t *testing.T, output string) (string, int64) {
	t.Helper()
	fields := strings.Fields(output)
	if len(fields) != 2 {
		t.Fatalf("unexpected save output: %q", output)
	}
	version, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return fields[0], version
}

func startCLITestServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := auth.NewManager(strings.Repeat("s", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := server.NewGRPCServer(server.NewService(storage.NewMemory(), manager), manager)
	go func() { _ = grpcServer.Serve(listener) }()
	return listener.Addr().String(), func() {
		grpcServer.Stop()
		_ = listener.Close()
	}
}

func TestMainContextIsUsable(t *testing.T) {
	root := NewRoot(BuildInfo{})
	root.SetContext(context.Background())
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
}
