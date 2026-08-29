// Command secret-mcp is an MCP server + CLI for AI-agent-safe secret
// management.
//
// MCP server mode (default, stdio transport):
//
//	secret-mcp -store ~/.secret-mcp
//
// CLI mode (subcommands, share the same encrypted store):
//
//	secret-mcp list                       # masked values only
//	secret-mcp get KEY                    # masked value (default)
//	secret-mcp get KEY --unsafe           # plaintext (last resort)
//	secret-mcp set KEY < value.txt        # read value from stdin, no echo
//	secret-mcp rotate KEY [length]        # generate + store new strong secret
//	secret-mcp delete KEY
//
// Security: plaintext values never appear in shell history, process lists, or
// command output — set reads from stdin, get masks by default.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sscodeai/secret-mcp/internal/leakscan"
	"github.com/sscodeai/secret-mcp/internal/mask"
	"github.com/sscodeai/secret-mcp/internal/mcp"
	"github.com/sscodeai/secret-mcp/internal/store"
	"github.com/sscodeai/secret-mcp/internal/vault"
)

var version = "0.3.0"

func main() {
	storeDir := flag.String("store", defaultStoreDir(), "directory holding age-encrypted secrets (key.txt + secrets.enc)")
	httpAddr := flag.String("http", "", "serve MCP over HTTP/SSE on this address (e.g. :8080) instead of stdio")
	streamable := flag.Bool("streamable", false, "with -http: use Streamable HTTP (MCP 2025) instead of SSE")
	vaultAddr := flag.String("vault", "", "HashiCorp Vault address (e.g. http://127.0.0.1:8200) — use Vault as backend")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("secret-mcp %s\n", version)
		return
	}

	args := flag.Args()

	// No subcommand → MCP server mode (stdio or HTTP/SSE).
	if len(args) == 0 {
		runMCPServer(*storeDir, *httpAddr, *vaultAddr, *streamable)
		return
	}

	// Subcommand → CLI mode.
	if err := runCLI(*storeDir, *vaultAddr, args); err != nil {
		log.Fatalf("secret-mcp: %v", err)
	}
}

func runMCPServer(storeDir, httpAddr, vaultAddr string, streamable bool) {
	st, err := store.New(storeDir)
	if err != nil {
		log.Fatalf("store init: %v", err)
	}
	srv, err := mcp.NewServer(st)
	if err != nil {
		log.Fatalf("mcp init: %v", err)
	}

	// HTTP mode: serve over HTTP (remote agents).
	// Default = SSE transport (GET /sse + POST endpoint).
	// With -streamable = MCP 2025 Streamable HTTP (single POST endpoint, JSON).
	if httpAddr != "" {
		var handler http.Handler
		if streamable {
			handler = sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv.Handler() },
				&sdk.StreamableHTTPOptions{JSONResponse: true, Stateless: true})
			log.Printf("secret-mcp serving MCP Streamable HTTP (stateless) on %s", httpAddr)
			log.Printf("  endpoint: http://localhost%s/mcp", httpAddr)
		} else {
			handler = sdk.NewSSEHandler(func(*http.Request) *sdk.Server { return srv.Handler() }, nil)
			log.Printf("secret-mcp serving MCP over SSE on %s", httpAddr)
			log.Printf("  endpoint: http://localhost%s/sse", httpAddr)
		}
		if err := http.ListenAndServe(httpAddr, handler); err != nil {
			log.Fatalf("http server: %v", err)
		}
		return
	}

	// stdio mode (default).
	if err := srv.Run(context.Background()); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func runCLI(storeDir, vaultAddr string, args []string) error {
	cmd := args[0]
	rest := args[1:]

	st, err := store.New(storeDir)
	if err != nil {
		return fmt.Errorf("store init: %w", err)
	}

	// Vault-backed commands need a Vault client.
	makeVault := func() (*vault.Client, error) {
		if vaultAddr == "" {
			return nil, fmt.Errorf("vault address required: pass -vault http://127.0.0.1:8200")
		}
		token := os.Getenv("VAULT_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("VAULT_TOKEN env var required")
		}
		return vault.NewClient(vaultAddr, token, "secret"), nil
	}

	switch cmd {
	case "list":
		items, err := st.List()
		if err != nil {
			return err
		}
		keys := make([]string, 0, len(items))
		for k := range items {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			fmt.Printf("%s=%s\n", k, items[k])
		}
		return nil

	case "get":
		if len(rest) < 1 {
			return fmt.Errorf("get requires a key: secret-mcp get KEY [--unsafe]")
		}
		key := rest[0]
		unsafe := containsFlag(rest, "--unsafe")
		val, err := st.Get(key)
		if err != nil {
			return err
		}
		if unsafe {
			fmt.Println(val)
		} else {
			fmt.Println(mask.Mask(val))
		}
		return nil

	case "set":
		if len(rest) < 1 {
			return fmt.Errorf("set requires a key: secret-mcp set KEY (value from stdin)")
		}
		key := rest[0]
		// Read value from stdin — never from argv (shell history / proc leak).
		val, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		value := strings.TrimSuffix(string(val), "\n")
		value = strings.TrimSuffix(value, "\r")
		if value == "" {
			return fmt.Errorf("empty value from stdin")
		}
		if err := st.Set(key, value); err != nil {
			return err
		}
		fmt.Printf("stored %s (masked: %s)\n", key, mask.Mask(value))
		return nil

	case "rotate":
		if len(rest) < 1 {
			return fmt.Errorf("rotate requires a key: secret-mcp rotate KEY [length]")
		}
		key := rest[0]
		length := 32
		if len(rest) >= 2 {
			if _, err := fmt.Sscanf(rest[1], "%d", &length); err != nil {
				return fmt.Errorf("invalid length %q", rest[1])
			}
		}
		masked, err := st.Rotate(key, length)
		if err != nil {
			return err
		}
		fmt.Printf("rotated %s -> %s\n", key, masked)
		return nil

	case "delete":
		if len(rest) < 1 {
			return fmt.Errorf("delete requires a key: secret-mcp delete KEY")
		}
		if err := st.Delete(rest[0]); err != nil {
			return err
		}
		fmt.Printf("deleted %s\n", rest[0])
		return nil

	case "scan":
		// secret-mcp scan [--rotate] [repo-dir]
		// Scans a git repo's history for leaked secrets. With --rotate,
		// matching store keys are auto-rotated (self-healing).
		repoDir := "."
		autoRotate := false
		for _, a := range rest {
			if a == "--rotate" {
				autoRotate = true
			} else if a != "" && !strings.HasPrefix(a, "-") {
				repoDir = a
			}
		}
		results, err := leakscan.ScanGitHistory(repoDir, st, autoRotate)
		if err != nil {
			return err
		}
		fmt.Print(leakscan.Format(results))
		return nil

	case "vault-kv-get":
		// secret-mcp vault-kv-get KEY  (masked by default, --unsafe for plaintext)
		if len(rest) < 1 {
			return fmt.Errorf("vault-kv-get requires a key")
		}
		vc, err := makeVault()
		if err != nil {
			return err
		}
		val, err := vc.GetKV(context.Background(), rest[0])
		if err != nil {
			return err
		}
		if containsFlag(rest, "--unsafe") {
			fmt.Println(val)
		} else {
			fmt.Println(mask.Mask(val))
		}
		return nil

	case "vault-kv-set":
		// secret-mcp vault-kv-set KEY  (value from stdin, no echo)
		if len(rest) < 1 {
			return fmt.Errorf("vault-kv-set requires a key")
		}
		vc, err := makeVault()
		if err != nil {
			return err
		}
		val, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		value := strings.TrimSuffix(string(val), "\n")
		value = strings.TrimSuffix(value, "\r")
		if value == "" {
			return fmt.Errorf("empty value from stdin")
		}
		if err := vc.SetKV(context.Background(), rest[0], value); err != nil {
			return err
		}
		fmt.Printf("stored %s in vault (masked: %s)\n", rest[0], mask.Mask(value))
		return nil

	case "vault-kv-list":
		vc, err := makeVault()
		if err != nil {
			return err
		}
		items, err := vc.ListKV(context.Background())
		if err != nil {
			return err
		}
		for k, v := range items {
			fmt.Printf("%s=%s\n", k, v)
		}
		return nil

	case "vault-db-creds":
		// secret-mcp vault-db-creds ROLE  — dynamic short-TTL DB credentials
		if len(rest) < 1 {
			return fmt.Errorf("vault-db-creds requires a role")
		}
		vc, err := makeVault()
		if err != nil {
			return err
		}
		creds, err := vc.GetDBCreds(context.Background(), rest[0])
		if err != nil {
			return err
		}
		fmt.Printf("username: %s\n", creds.Username)
		fmt.Printf("password: %s (masked)\n", mask.Mask(creds.Password))
		fmt.Printf("lease_id: %s\n", creds.LeaseID)
		fmt.Printf("ttl: %ds (auto-expires — leaked cred is harmless)\n", creds.LeaseTTL)
		fmt.Printf("renewable: %v\n", creds.Renewable)
		return nil

	case "help", "-h", "--help":
		printUsage()
		return nil

	default:
		return fmt.Errorf("unknown command %q\n%s", cmd, usageText())
	}
}

func printUsage() {
	fmt.Print(usageText())
}

func usageText() string {
	return `secret-mcp — AI-agent-safe secret management (Go)

USAGE:
  secret-mcp                    # MCP server mode (stdio transport)
  secret-mcp list               # all keys, masked values
  secret-mcp get KEY            # masked value (add --unsafe for plaintext)
  secret-mcp set KEY            # store value read from stdin (no echo)
  secret-mcp rotate KEY [len]   # generate + store new strong secret
  secret-mcp delete KEY         # remove a key
  secret-mcp scan [--rotate] [repo-dir]  # scan git history for leaked secrets
  secret-mcp -version

FLAGS:
  -store DIR   store directory (default ~/.secret-mcp or $SECRET_MCP_STORE)

SECURITY:
  - set reads the value from stdin — never pass secrets as arguments
  - get/list return masked values by default (sk******ij)
  - --unsafe is the ONLY way to see plaintext — use as a last resort
  - secrets are stored age-encrypted at rest (key.txt 0600, secrets.enc armor)
`
}

func containsFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
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
