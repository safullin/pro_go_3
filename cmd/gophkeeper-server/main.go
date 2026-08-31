package main

import (
	"context"
	"errors"
	"fmt"
	"log"
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
	if err := run(os.Args[1:]); err != nil {
		log.Printf("server stopped: %v", err)
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
	defer store.Close()
	tokens, err := auth.NewManager(cfg.AuthSecret, cfg.TokenLifetime)
	if err != nil {
		return err
	}
	options := make([]grpc.ServerOption, 0, 1)
	if cfg.TLSCert != "" {
		transport, loadErr := credentials.NewServerTLSFromFile(cfg.TLSCert, cfg.TLSKey)
		if loadErr != nil {
			return fmt.Errorf("load TLS certificate: %w", loadErr)
		}
		options = append(options, grpc.Creds(transport))
	}
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Address, err)
	}
	defer listener.Close()
	grpcServer := server.NewGRPCServer(server.NewService(store, tokens), tokens, options...)
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- grpcServer.Serve(listener)
	}()
	log.Printf("GophKeeper server is listening on %s", cfg.Address)
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
