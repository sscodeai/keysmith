// Command secret-mcp is an MCP server for AI-agent-safe secret management.
//
// It exposes secrets as masked resources + controlled tools over the Model
// Context Protocol (stdio transport). Plaintext never appears in tool results
// or resources; secrets are stored age-encrypted at rest.
//
// Usage:
//
//	secret-mcp -store ~/.secret-mcp        # store dir (default ~/.secret-mcp)
//	secret-mcp -version                    # print version
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/sscodeai/secret-mcp/internal/mcp"
	"github.com/sscodeai/secret-mcp/internal/store"
)

var version = "0.1.0"

func main() {
	var (
		storeDir = flag.String("store", defaultStoreDir(), "directory holding age-encrypted secrets (key.txt + secrets.enc)")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("secret-mcp %s\n", version)
		return
	}

	st, err := store.New(*storeDir)
	if err != nil {
		log.Fatalf("store init: %v", err)
	}

	srv, err := mcp.NewServer(st)
	if err != nil {
		log.Fatalf("mcp init: %v", err)
	}

	if err := srv.Run(context.Background()); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func defaultStoreDir() string {
	if v := os.Getenv("SECRET_MCP_STORE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".secret-mcp"
	}
	return filepath.Join(home, ".secret-mcp")
}
