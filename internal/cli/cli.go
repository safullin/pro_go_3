package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/safullin/pro_go_3/internal/client"
	"github.com/safullin/pro_go_3/internal/config"
	"github.com/safullin/pro_go_3/internal/domain"
)

// BuildInfo contains values injected into the client binary at build time.
type BuildInfo struct {
	Version string
	Date    string
	Commit  string
}

type application struct {
	build        BuildInfo
	address      string
	caFile       string
	serverName   string
	timeout      time.Duration
	sessionFile  string
	cacheFile    string
	readPassword func() (string, error)
	stdin        io.Reader
	stdout       io.Writer
	stderr       io.Writer
}

// NewRoot builds the root GophKeeper CLI command.
func NewRoot(build BuildInfo) *cobra.Command {
	app := &application{
		build:      build,
		address:    envString("GOPHKEEPER_ADDRESS", "127.0.0.1:3200"),
		caFile:     os.Getenv("GOPHKEEPER_CA"),
		serverName: os.Getenv("GOPHKEEPER_SERVER_NAME"),
		timeout:    envDuration("GOPHKEEPER_TIMEOUT", 15*time.Second),
		stdin:      os.Stdin,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
	}
	app.sessionFile, _ = client.DefaultSessionPath()
	if value := os.Getenv("GOPHKEEPER_SESSION"); value != "" {
		app.sessionFile = value
	}
	app.cacheFile = app.sessionFile + ".cache"
	if value := os.Getenv("GOPHKEEPER_CACHE"); value != "" {
		app.cacheFile = value
	}
	app.readPassword = func() (string, error) { return readTerminalPassword(os.Stdin, os.Stderr) }
	return newRoot(app)
}

func newRoot(app *application) *cobra.Command {
	root := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "Encrypted private data manager",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(app.stdin)
	root.SetOut(app.stdout)
	root.SetErr(app.stderr)
	flags := root.PersistentFlags()
	flags.StringVarP(&app.address, "address", "a", app.address, "gRPC server address")
	flags.StringVar(&app.caFile, "ca", app.caFile, "server CA certificate")
	flags.StringVar(&app.serverName, "server-name", app.serverName, "TLS server name")
	flags.DurationVar(&app.timeout, "timeout", app.timeout, "request timeout")
	flags.StringVar(&app.sessionFile, "session", app.sessionFile, "session file")
	flags.StringVar(&app.cacheFile, "cache", app.cacheFile, "encrypted local cache file")
	root.AddCommand(
		app.registerCommand(),
		app.loginCommand(),
		app.addCommand(),
		app.updateCommand(),
		app.listCommand(),
		app.getCommand(),
		app.searchCommand(),
		app.deleteCommand(),
		app.syncCommand(),
		app.versionCommand(),
	)
	return root
}

func (a *application) registerCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "register LOGIN",
		Short: "Register a new account",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			password, err := a.masterPassword()
			if err != nil {
				return err
			}
			api, err := a.connect()
			if err != nil {
				return err
			}
			defer func() { _ = api.Close() }()
			ctx, cancel := context.WithTimeout(command.Context(), a.timeout)
			defer cancel()
			session, err := api.Register(ctx, args[0], password, a.address)
			if err != nil {
				return fmt.Errorf("register: %w", err)
			}
			if err = client.SaveSession(a.sessionFile, session); err != nil {
				return err
			}
			_, err = fmt.Fprintln(a.stdout, "Account registered")
			return err
		},
	}
}

func (a *application) loginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login LOGIN",
		Short: "Authenticate an existing account",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			password, err := a.masterPassword()
			if err != nil {
				return err
			}
			api, err := a.connect()
			if err != nil {
				return err
			}
			defer func() { _ = api.Close() }()
			ctx, cancel := context.WithTimeout(command.Context(), a.timeout)
			defer cancel()
			session, err := api.Login(ctx, args[0], password, a.address)
			if err != nil {
				return fmt.Errorf("login: %w", err)
			}
			if err = client.SaveSession(a.sessionFile, session); err != nil {
				return err
			}
			_, err = fmt.Fprintln(a.stdout, "Authenticated")
			return err
		},
	}
}

func (a *application) addCommand() *cobra.Command {
	command := &cobra.Command{Use: "add", Short: "Add private data"}
	command.AddCommand(
		a.putCredentialsCommand(false),
		a.putTextCommand(false),
		a.putBinaryCommand(false),
		a.putCardCommand(false),
	)
	return command
}

func (a *application) updateCommand() *cobra.Command {
	command := &cobra.Command{Use: "update", Short: "Update private data"}
	command.AddCommand(
		a.putCredentialsCommand(true),
		a.putTextCommand(true),
		a.putBinaryCommand(true),
		a.putCardCommand(true),
	)
	return command
}

func (a *application) putCredentialsCommand(update bool) *cobra.Command {
	var name, metadataValue, login, password string
	command := &cobra.Command{
		Use:   putUsage("credentials", update),
		Short: "Store a login and password",
		Args:  putArgs(update),
		RunE: func(command *cobra.Command, args []string) error {
			payload := domain.Payload{Name: name, Metadata: metadataValue, Credentials: &domain.Credentials{Login: login, Password: password}}
			return a.put(command, args, update, domain.SecretKindCredentials, payload)
		},
	}
	command.Flags().StringVar(&name, "name", "", "entry name")
	command.Flags().StringVar(&metadataValue, "metadata", "", "text metadata")
	command.Flags().StringVar(&login, "login", "", "stored login")
	command.Flags().StringVar(&password, "secret", "", "stored password")
	return command
}

func (a *application) putTextCommand(update bool) *cobra.Command {
	var name, metadataValue, value string
	command := &cobra.Command{
		Use:   putUsage("text", update),
		Short: "Store arbitrary text",
		Args:  putArgs(update),
		RunE: func(command *cobra.Command, args []string) error {
			payload := domain.Payload{Name: name, Metadata: metadataValue, Text: &domain.TextData{Value: value}}
			return a.put(command, args, update, domain.SecretKindText, payload)
		},
	}
	command.Flags().StringVar(&name, "name", "", "entry name")
	command.Flags().StringVar(&metadataValue, "metadata", "", "text metadata")
	command.Flags().StringVar(&value, "text", "", "stored text")
	return command
}

func (a *application) putBinaryCommand(update bool) *cobra.Command {
	var name, metadataValue, fileName string
	command := &cobra.Command{
		Use:   putUsage("binary", update),
		Short: "Store a binary file",
		Args:  putArgs(update),
		RunE: func(command *cobra.Command, args []string) error {
			data, err := os.ReadFile(fileName)
			if err != nil {
				return fmt.Errorf("read binary file: %w", err)
			}
			if len(data) > 15<<20 {
				return errors.New("binary file is larger than 15 MiB")
			}
			payload := domain.Payload{Name: name, Metadata: metadataValue, Binary: &domain.BinaryData{FileName: filepath.Base(fileName), Data: data}}
			return a.put(command, args, update, domain.SecretKindBinary, payload)
		},
	}
	command.Flags().StringVar(&name, "name", "", "entry name")
	command.Flags().StringVar(&metadataValue, "metadata", "", "text metadata")
	command.Flags().StringVar(&fileName, "file", "", "binary file path")
	return command
}

func (a *application) putCardCommand(update bool) *cobra.Command {
	var name, metadataValue, number, holder, expiry, cvv string
	command := &cobra.Command{
		Use:   putUsage("card", update),
		Short: "Store bank card details",
		Args:  putArgs(update),
		RunE: func(command *cobra.Command, args []string) error {
			payload := domain.Payload{Name: name, Metadata: metadataValue, Card: &domain.CardData{Number: number, Holder: holder, Expiry: expiry, CVV: cvv}}
			return a.put(command, args, update, domain.SecretKindCard, payload)
		},
	}
	command.Flags().StringVar(&name, "name", "", "entry name")
	command.Flags().StringVar(&metadataValue, "metadata", "", "text metadata")
	command.Flags().StringVar(&number, "number", "", "card number")
	command.Flags().StringVar(&holder, "holder", "", "card holder")
	command.Flags().StringVar(&expiry, "expiry", "", "expiration date")
	command.Flags().StringVar(&cvv, "cvv", "", "card verification value")
	return command
}

func (a *application) put(command *cobra.Command, args []string, update bool, kind domain.SecretKind, payload domain.Payload) error {
	id := ""
	version := int64(0)
	if update {
		id = args[0]
		parsed, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || parsed <= 0 {
			return errors.New("version must be a positive integer")
		}
		version = parsed
	}
	return a.withAuthenticated(command, func(ctx context.Context, api *client.Client) error {
		entry, err := api.Put(ctx, id, kind, payload, version)
		if err != nil {
			return fmt.Errorf("save entry: %w", err)
		}
		a.refreshCache(ctx, api)
		_, err = fmt.Fprintf(a.stdout, "%s\t%d\n", entry.Secret.ID, entry.Secret.Version)
		return err
	})
}

func (a *application) listCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List current private data",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return a.withOnlineFallback(command,
				func(ctx context.Context, api *client.Client) error {
					result, err := api.SyncToCache(ctx, 0, a.cacheFile)
					if err != nil {
						return fmt.Errorf("list entries: %w", err)
					}
					return a.printEntries(result.Entries)
				},
				func(api *client.Client) error {
					result, err := api.ReadCache(a.cacheFile)
					if err != nil {
						return fmt.Errorf("read offline cache: %w", err)
					}
					return a.printEntries(result.Entries)
				},
			)
		},
	}
}

func (a *application) getCommand() *cobra.Command {
	var output string
	command := &cobra.Command{
		Use:   "get ID",
		Short: "Show private data",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			return a.withOnlineFallback(command,
				func(ctx context.Context, api *client.Client) error {
					entry, err := api.Get(ctx, args[0])
					if err != nil {
						return fmt.Errorf("get entry: %w", err)
					}
					a.refreshCache(ctx, api)
					return a.printEntry(entry, output)
				},
				func(api *client.Client) error {
					entry, err := api.GetCached(a.cacheFile, args[0])
					if err != nil {
						return fmt.Errorf("read offline cache: %w", err)
					}
					return a.printEntry(entry, output)
				},
			)
		},
	}
	command.Flags().StringVarP(&output, "output", "o", "", "output path for binary data")
	return command
}

func (a *application) searchCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "search QUERY",
		Short: "Search private data by name or metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			return a.withOnlineFallback(command,
				func(ctx context.Context, api *client.Client) error {
					entries, err := api.Search(ctx, args[0])
					if err != nil {
						return fmt.Errorf("search entries: %w", err)
					}
					return a.printEntries(entries)
				},
				func(api *client.Client) error {
					entries, err := api.SearchCached(a.cacheFile, args[0])
					if err != nil {
						return fmt.Errorf("search offline cache: %w", err)
					}
					return a.printEntries(entries)
				},
			)
		},
	}
}

func (a *application) deleteCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete ID VERSION",
		Short: "Delete private data",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			version, err := strconv.ParseInt(args[1], 10, 64)
			if err != nil || version <= 0 {
				return errors.New("version must be a positive integer")
			}
			return a.withAuthenticated(command, func(ctx context.Context, api *client.Client) error {
				if err = api.Delete(ctx, args[0], version); err != nil {
					return fmt.Errorf("delete entry: %w", err)
				}
				a.refreshCache(ctx, api)
				_, err = fmt.Fprintln(a.stdout, "Deleted")
				return err
			})
		},
	}
}

func (a *application) syncCommand() *cobra.Command {
	var since int64
	command := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize changes from the server",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if since < 0 {
				return errors.New("cursor cannot be negative")
			}
			return a.withAuthenticated(command, func(ctx context.Context, api *client.Client) error {
				result, err := api.SyncToCache(ctx, since, a.cacheFile)
				if err != nil {
					return fmt.Errorf("synchronize entries: %w", err)
				}
				if _, err = fmt.Fprintf(a.stdout, "Changes: %d, deleted: %d, cursor: %d\n", len(result.Entries), len(result.Deleted), result.Cursor); err != nil {
					return err
				}
				for _, entry := range result.Entries {
					if _, err = fmt.Fprintf(a.stdout, "%s\t%s\t%d\t%s\n", entry.Secret.ID, entry.Secret.Kind, entry.Secret.Version, entry.Payload.Name); err != nil {
						return err
					}
				}
				for _, id := range result.Deleted {
					if _, err = fmt.Fprintf(a.stdout, "%s\tdeleted\n", id); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	command.Flags().Int64Var(&since, "since", 0, "synchronization cursor")
	return command
}

func (a *application) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print client build information",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(a.stdout, "Build version: %s\nBuild date: %s\nBuild commit: %s\n",
				buildValue(a.build.Version), buildValue(a.build.Date), buildValue(a.build.Commit))
			return err
		},
	}
}

func (a *application) withAuthenticated(command *cobra.Command, action func(context.Context, *client.Client) error) error {
	session, password, err := a.loadCredentials()
	if err != nil {
		return err
	}
	api, err := a.connect()
	if err != nil {
		return err
	}
	defer func() { _ = api.Close() }()
	if err = api.Restore(session, password); err != nil {
		return fmt.Errorf("restore session: %w", err)
	}
	ctx, cancel := context.WithTimeout(command.Context(), a.timeout)
	defer cancel()
	return action(ctx, api)
}

func (a *application) withOnlineFallback(command *cobra.Command, online func(context.Context, *client.Client) error, offline func(*client.Client) error) error {
	session, password, err := a.loadCredentials()
	if err != nil {
		return err
	}
	api, connectErr := a.connect()
	if connectErr != nil {
		api = client.NewOffline()
	}
	defer func() { _ = api.Close() }()
	if err = api.Restore(session, password); err != nil {
		return fmt.Errorf("restore session: %w", err)
	}
	if connectErr != nil {
		return offline(api)
	}
	ctx, cancel := context.WithTimeout(command.Context(), a.timeout)
	defer cancel()
	if err = online(ctx, api); err == nil {
		return nil
	}
	if !client.IsUnavailable(err) {
		return err
	}
	return offline(api)
}

func (a *application) loadCredentials() (client.Session, string, error) {
	session, err := client.LoadSession(a.sessionFile)
	if err != nil {
		return client.Session{}, "", fmt.Errorf("load session: %w", err)
	}
	password, err := a.masterPassword()
	if err != nil {
		return client.Session{}, "", err
	}
	return session, password, nil
}

func (a *application) connect() (*client.Client, error) {
	if a.timeout <= 0 {
		return nil, errors.New("timeout must be positive")
	}
	if a.caFile == "" {
		return nil, errors.New("CA certificate is required")
	}
	return client.Dial(config.Client{
		Address:     a.address,
		CAFile:      a.caFile,
		ServerName:  a.serverName,
		Timeout:     a.timeout,
		SessionFile: a.sessionFile,
	})
}

func (a *application) masterPassword() (string, error) {
	if a.readPassword == nil {
		return "", errors.New("master password reader is not configured")
	}
	return a.readPassword()
}

func readTerminalPassword(stdin *os.File, stderr io.Writer) (string, error) {
	if !term.IsTerminal(int(stdin.Fd())) {
		return "", errors.New("master password requires an interactive terminal")
	}
	if _, err := fmt.Fprint(stderr, "Master password: "); err != nil {
		return "", fmt.Errorf("write password prompt: %w", err)
	}
	value, err := term.ReadPassword(int(stdin.Fd()))
	_, newlineErr := fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read master password: %w", err)
	}
	if newlineErr != nil {
		return "", fmt.Errorf("write password prompt: %w", newlineErr)
	}
	if len(value) == 0 {
		return "", errors.New("master password is required")
	}
	return string(value), nil
}

func (a *application) refreshCache(ctx context.Context, api *client.Client) {
	if _, err := api.SyncToCache(ctx, 0, a.cacheFile); err != nil {
		_, _ = fmt.Fprintf(a.stderr, "Local cache was not updated: %v\n", err)
	}
}

func (a *application) printEntries(entries []domain.Entry) error {
	writer := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "ID\tTYPE\tVERSION\tUPDATED\tNAME\tMETADATA"); err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%d\t%s\t%s\t%s\n",
			entry.Secret.ID, entry.Secret.Kind, entry.Secret.Version,
			entry.Secret.UpdatedAt.Format(time.RFC3339), entry.Secret.Name, entry.Secret.Metadata); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func (a *application) printEntry(entry domain.Entry, output string) error {
	if _, err := fmt.Fprintf(a.stdout, "ID: %s\nType: %s\nVersion: %d\nName: %s\nMetadata: %s\n",
		entry.Secret.ID, entry.Secret.Kind, entry.Secret.Version, entry.Payload.Name, entry.Payload.Metadata); err != nil {
		return err
	}
	switch entry.Secret.Kind {
	case domain.SecretKindCredentials:
		_, err := fmt.Fprintf(a.stdout, "Login: %s\nPassword: %s\n", entry.Payload.Credentials.Login, entry.Payload.Credentials.Password)
		return err
	case domain.SecretKindText:
		_, err := fmt.Fprintln(a.stdout, entry.Payload.Text.Value)
		return err
	case domain.SecretKindBinary:
		if output == "" {
			return errors.New("output path is required for binary data")
		}
		if err := os.WriteFile(output, entry.Payload.Binary.Data, 0o600); err != nil {
			return fmt.Errorf("write binary file: %w", err)
		}
		_, err := fmt.Fprintf(a.stdout, "Saved to %s\n", output)
		return err
	case domain.SecretKindCard:
		_, err := fmt.Fprintf(a.stdout, "Number: %s\nHolder: %s\nExpiry: %s\nCVV: %s\n",
			entry.Payload.Card.Number, entry.Payload.Card.Holder, entry.Payload.Card.Expiry, entry.Payload.Card.CVV)
		return err
	}
	return nil
}

func putUsage(kind string, update bool) string {
	if update {
		return kind + " ID VERSION"
	}
	return kind
}

func putArgs(update bool) cobra.PositionalArgs {
	if update {
		return cobra.ExactArgs(2)
	}
	return cobra.NoArgs
}

func envString(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return value
}

func buildValue(value string) string {
	if value == "" {
		return "N/A"
	}
	return value
}
