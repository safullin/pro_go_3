package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/safullin/pro_go_3/internal/auth"
	"github.com/safullin/pro_go_3/internal/config"
	"github.com/safullin/pro_go_3/internal/server"
	"github.com/safullin/pro_go_3/internal/storage"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(os.Args[1:]); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.ParseServer(args)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()
	store, err := storage.NewPostgres(ctx, cfg.DatabaseURI)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			slog.Error("database close failed", "error", closeErr)
		}
	}()
	tokens, err := auth.NewManager(cfg.AuthSecret, cfg.TokenLifetime)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	transport := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Address, err)
	}
	defer func() { _ = listener.Close() }()
	grpcServer := server.NewGRPCServer(server.NewService(store, tokens), tokens, transport)
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- grpcServer.Serve(listener)
	}()
	slog.Info("server started", "address", cfg.Address)
	select {
	case err = <-serveErrors:
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	case <-ctx.Done():
		gracefulDone := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(gracefulDone)
		}()
		select {
		case <-gracefulDone:
		case <-time.After(10 * time.Second):
			grpcServer.Stop()
		}
		return nil
	}
}
