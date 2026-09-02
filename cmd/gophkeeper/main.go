package main

import (
	"log/slog"
	"os"

	"github.com/safullin/pro_go_3/internal/cli"
)

var (
	buildVersion = "N/A"
	buildDate    = "N/A"
	buildCommit  = "N/A"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := execute(os.Args[1:]); err != nil {
		slog.Error("client stopped", "error", err)
		os.Exit(1)
	}
}

func execute(args []string) error {
	root := cli.NewRoot(cli.BuildInfo{Version: buildVersion, Date: buildDate, Commit: buildCommit})
	root.SetArgs(args)
	return root.Execute()
}
