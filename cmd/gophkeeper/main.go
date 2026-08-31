package main

import (
	"log"
	"os"

	"github.com/safullin/pro_go_3/internal/cli"
)

var (
	buildVersion = "N/A"
	buildDate    = "N/A"
	buildCommit  = "N/A"
)

func main() {
	if err := execute(os.Args[1:]); err != nil {
		log.Printf("gophkeeper: %v", err)
	}
}

func execute(args []string) error {
	root := cli.NewRoot(cli.BuildInfo{Version: buildVersion, Date: buildDate, Commit: buildCommit})
	root.SetArgs(args)
	return root.Execute()
}
