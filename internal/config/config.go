package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

// Server contains GophKeeper server settings.
type Server struct {
	Address       string
	DatabaseURI   string
	AuthSecret    string
	TLSCert       string
	TLSKey        string
	TokenLifetime time.Duration
}

// ParseServer reads server flags and lets environment variables override them.
func ParseServer(args []string) (Server, error) {
	var cfg Server
	flags := flag.NewFlagSet("gophkeeper-server", flag.ContinueOnError)
	flags.StringVar(&cfg.Address, "a", "127.0.0.1:3200", "gRPC listen address")
	flags.StringVar(&cfg.DatabaseURI, "d", "", "PostgreSQL connection string")
	flags.StringVar(&cfg.AuthSecret, "auth-secret", "", "authorization signing secret")
	flags.StringVar(&cfg.TLSCert, "tls-cert", "", "TLS certificate path")
	flags.StringVar(&cfg.TLSKey, "tls-key", "", "TLS private key path")
	flags.DurationVar(&cfg.TokenLifetime, "token-ttl", 24*time.Hour, "authorization token lifetime")
	if err := flags.Parse(args); err != nil {
		return Server{}, err
	}
	setStringFromEnv(&cfg.Address, "RUN_ADDRESS")
	setStringFromEnv(&cfg.DatabaseURI, "DATABASE_URI")
	setStringFromEnv(&cfg.AuthSecret, "AUTH_SECRET")
	setStringFromEnv(&cfg.TLSCert, "TLS_CERT")
	setStringFromEnv(&cfg.TLSKey, "TLS_KEY")
	if value, ok := os.LookupEnv("TOKEN_TTL"); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Server{}, fmt.Errorf("parse TOKEN_TTL: %w", err)
		}
		cfg.TokenLifetime = duration
	}
	if cfg.DatabaseURI == "" {
		return Server{}, errors.New("database connection string is required")
	}
	if len(cfg.AuthSecret) < 32 {
		return Server{}, errors.New("authorization secret must contain at least 32 characters")
	}
	if cfg.TLSCert == "" || cfg.TLSKey == "" {
		return Server{}, errors.New("TLS certificate and key are required")
	}
	if cfg.TokenLifetime <= 0 {
		return Server{}, errors.New("token lifetime must be positive")
	}
	return cfg, nil
}

// Client contains GophKeeper CLI connection settings.
type Client struct {
	Address     string
	CAFile      string
	ServerName  string
	Timeout     time.Duration
	SessionFile string
}

// ParseClient reads client flags and lets environment variables override them.
func ParseClient(args []string) (Client, error) {
	var cfg Client
	flags := flag.NewFlagSet("gophkeeper", flag.ContinueOnError)
	flags.StringVar(&cfg.Address, "a", "127.0.0.1:3200", "gRPC server address")
	flags.StringVar(&cfg.CAFile, "ca", "", "server CA certificate path")
	flags.StringVar(&cfg.ServerName, "server-name", "", "TLS server name")
	flags.DurationVar(&cfg.Timeout, "timeout", 15*time.Second, "request timeout")
	flags.StringVar(&cfg.SessionFile, "session", "", "session file path")
	if err := flags.Parse(args); err != nil {
		return Client{}, err
	}
	setStringFromEnv(&cfg.Address, "GOPHKEEPER_ADDRESS")
	setStringFromEnv(&cfg.CAFile, "GOPHKEEPER_CA")
	setStringFromEnv(&cfg.ServerName, "GOPHKEEPER_SERVER_NAME")
	setStringFromEnv(&cfg.SessionFile, "GOPHKEEPER_SESSION")
	if value, ok := os.LookupEnv("GOPHKEEPER_TIMEOUT"); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Client{}, fmt.Errorf("parse GOPHKEEPER_TIMEOUT: %w", err)
		}
		cfg.Timeout = duration
	}
	if cfg.Address == "" {
		return Client{}, errors.New("server address is required")
	}
	if cfg.CAFile == "" {
		return Client{}, errors.New("CA certificate is required")
	}
	if cfg.Timeout <= 0 {
		return Client{}, errors.New("request timeout must be positive")
	}
	return cfg, nil
}

func setStringFromEnv(destination *string, name string) {
	if value, ok := os.LookupEnv(name); ok {
		*destination = value
	}
}
