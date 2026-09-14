// Command keysmith is an MCP server + CLI for AI-agent-safe secret
// management.
//
// MCP server mode (default, stdio transport):
//
//	keysmith -store ~/.keysmith
//
// CLI mode (subcommands, share the same encrypted store):
//
//	keysmith list                       # masked values only
//	keysmith get KEY                    # masked value (default)
//	keysmith get KEY --unsafe           # plaintext (last resort)
//	keysmith set KEY < value.txt        # read value from stdin, no echo
//	keysmith rotate KEY [length]        # generate + store new strong secret
//	keysmith delete KEY
//
// Security: plaintext values never appear in shell history, process lists, or
// command output — set reads from stdin, get masks by default.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sscodeai/keysmith/internal/leakscan"
	"github.com/sscodeai/keysmith/internal/mask"
	"github.com/sscodeai/keysmith/internal/mcp"
	"github.com/sscodeai/keysmith/internal/redeem"
	"github.com/sscodeai/keysmith/internal/store"
	"github.com/sscodeai/keysmith/internal/vault"
)

var version = "0.4.0"

func main() {
	storeDir := flag.String("store", defaultStoreDir(), "directory holding age-encrypted secrets (key.txt + secrets.enc)")
	httpAddr := flag.String("http", "", "serve MCP over HTTP/SSE on this address (e.g. :8080) instead of stdio")
	streamable := flag.Bool("streamable", false, "with -http: use Streamable HTTP (MCP 2025) instead of SSE")
	vaultAddr := flag.String("vault", "", "HashiCorp Vault address (e.g. http://127.0.0.1:8200) — use Vault as backend")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("keysmith %s\n", version)
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
		log.Fatalf("keysmith: %v", err)
	}
}

func runMCPServer(storeDir, httpAddr, vaultAddr string, streamable bool) {
	st, err := store.New(storeDir)
	if err != nil {
		log.Fatalf("store init: %v", err)
	}
	srv, err := mcp.NewServer(st, version)
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
			log.Printf("keysmith serving MCP Streamable HTTP (stateless) on %s", httpAddr)
			log.Printf("  endpoint: http://localhost%s/mcp", httpAddr)
		} else {
			handler = sdk.NewSSEHandler(func(*http.Request) *sdk.Server { return srv.Handler() }, nil)
			log.Printf("keysmith serving MCP over SSE on %s", httpAddr)
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
			return fmt.Errorf("get requires a key: keysmith get KEY [--unsafe]")
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
			return fmt.Errorf("set requires a key: keysmith set KEY (value from stdin)")
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
			return fmt.Errorf("rotate requires a key: keysmith rotate KEY [length]")
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
			return fmt.Errorf("delete requires a key: keysmith delete KEY")
		}
		if err := st.Delete(rest[0]); err != nil {
			return err
		}
		fmt.Printf("deleted %s\n", rest[0])
		return nil

	case "scan":
		// keysmith scan [--rotate] [repo-dir]
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
		// keysmith vault-kv-get KEY  (masked by default, --unsafe for plaintext)
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
		// keysmith vault-kv-set KEY  (value from stdin, no echo)
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
		// keysmith vault-db-creds ROLE  — dynamic short-TTL DB credentials
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

	case "token":
		// keysmith token NAME [--ttl 1h]
		// Issue a session-bound placeholder for NAME. The token is a reference,
		// not a secret: it only resolves locally, only in this session, and only
		// for the names issued here.
		if len(rest) < 1 {
			return fmt.Errorf("token requires a key name: keysmith token NAME [--ttl 1h]")
		}
		name := rest[0]
		ttl := redeem.DefaultTTL
		if v, ok := flagValue(rest, "--ttl"); ok {
			d, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("invalid --ttl %q: %w", v, err)
			}
			ttl = d
		}
		// Fail closed: never issue a token for a name this store cannot resolve.
		if _, err := st.Get(name); err != nil {
			return fmt.Errorf("cannot issue a token for %q: %w", name, err)
		}
		sess, err := redeem.NewSessions(storeDir).Issue(name, ttl)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "keysmith: session %s (names: %s), expires at %s\n",
			sess.ID[:8], strings.Join(sess.Names, ","),
			sess.ExpiresAt.Local().Format(time.RFC3339))
		fmt.Println(sess.Token(name))
		return nil

	case "run":
		// keysmith run [--session SID] --env KEY='<template>' ... -- cmd args...
		return runRedeemed(storeDir, st, rest)

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
	return `keysmith — AI-agent-safe secret management (Go)

USAGE:
  keysmith                    # MCP server mode (stdio transport)
  keysmith list               # all keys, masked values
  keysmith get KEY            # masked value (add --unsafe for plaintext)
  keysmith set KEY            # store value read from stdin (no echo)
  keysmith rotate KEY [len]   # generate + store new strong secret
  keysmith delete KEY         # remove a key
  keysmith scan [--rotate] [repo-dir]  # scan git history for leaked secrets
  keysmith token NAME [--ttl 1h]       # issue a session-bound placeholder token
  keysmith run [--session SID] --env KEY='<template>' -- cmd args...
                                       # redeem tokens locally, then run cmd
  keysmith -version

FLAGS:
  -store DIR   store directory (default ~/.keysmith or $KEYSMITH_STORE)

SECURITY:
  - set reads the value from stdin — never pass secrets as arguments
  - get/list return masked values by default (sk******ij)
  - --unsafe is the ONLY way to see plaintext — use as a last resort
  - run keeps values out of argv, out of the transcript, and out of any
    model request: tokens are redeemed locally, into the child's environment
  - redemption fails closed: any error aborts the command, with no fallback
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

// flagValue returns the value of "--name value" or "--name=value".
func flagValue(args []string, name string) (string, bool) {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1], true
		}
		if strings.HasPrefix(a, name+"=") {
			return strings.TrimPrefix(a, name+"="), true
		}
	}
	return "", false
}

const runUsage = `usage: keysmith run [--session SID] --env KEY='<template>' [--env ...] -- <command> [args...]

  Each --env value is a template. A [[keysmith:v1:NAME:sid]] token inside it is
  replaced with the real value before the command starts, and the result is put
  into the child's environment under KEY. The value never appears in the command
  arguments, in this process's argv, or in any model request.

  Issue tokens first:  TOKEN=$(keysmith token DB_PASSWORD)
  Then:                keysmith run --env AUTH="Bearer $TOKEN" -- sh -c 'curl -H "Authorization: $AUTH" https://example.test'`

// runRedeemed implements `keysmith run`: resolve tokens inside --env templates
// locally, then exec the command with the values in its environment.
//
// Fail-closed behaviour (docs/THREAT-MODEL.md):
//   - a token in the command arguments is refused: argv is visible to every
//     user on the box through ps, so values must travel in the environment
//   - any resolution failure, and any failure to write the audit record,
//     aborts before the child process starts
//
// Argument handling is split into pure helpers (parseRunArgs,
// checkNoTokensInCommand, parseEnvTemplate) so it can be unit tested.

// runOptions is the parsed form of `keysmith run` arguments.
type runOptions struct {
	Envs    []string // KEY=<template>
	Session string
	Command []string
}

// parseRunArgs splits `run` arguments into options and the command after --.
// Pure, so the fail-closed argument handling can be unit tested.
func parseRunArgs(rest []string, sessionEnv string) (runOptions, error) {
	opts := runOptions{Session: sessionEnv}
	i := 0
parse:
	for i < len(rest) {
		switch a := rest[i]; {
		case a == "--":
			i++
			break parse
		case a == "--env" && i+1 < len(rest):
			opts.Envs = append(opts.Envs, rest[i+1])
			i += 2
		case strings.HasPrefix(a, "--env="):
			opts.Envs = append(opts.Envs, strings.TrimPrefix(a, "--env="))
			i++
		case a == "--session" && i+1 < len(rest):
			opts.Session = rest[i+1]
			i += 2
		case strings.HasPrefix(a, "--session="):
			opts.Session = strings.TrimPrefix(a, "--session=")
			i++
		default:
			return runOptions{}, fmt.Errorf("run: unexpected argument %q (options must come before --)\n\n%s", a, runUsage)
		}
	}
	opts.Command = rest[i:]
	return opts, nil
}

// checkNoTokensInCommand refuses a token carried in the command arguments:
// argv is readable by every user on the machine through ps.
func checkNoTokensInCommand(cmd []string) error {
	for _, a := range cmd {
		if redeem.HasToken(a) {
			return errors.New("run: refusing a keysmith token in the command arguments — argv is readable by every user via ps\n" +
				"carry it in the environment instead, for example:\n" +
				"  keysmith run --env AUTH='Bearer [[keysmith:v1:NAME:sid]]' -- sh -c 'curl -H \"Authorization: $AUTH\" https://example.test'")
		}
	}
	return nil
}

// parseEnvTemplate splits an --env value of the form KEY=<template>.
func parseEnvTemplate(tpl string) (key, template string, err error) {
	eq := strings.Index(tpl, "=")
	if eq <= 0 {
		return "", "", fmt.Errorf("run: --env expects KEY=<template>, got %q", tpl)
	}
	if !validEnvName(tpl[:eq]) {
		return "", "", fmt.Errorf("run: --env name %q is not a valid environment variable name", tpl[:eq])
	}
	return tpl[:eq], tpl[eq+1:], nil
}

// runRedeemed resolves tokens inside the --env templates and then starts the
// command with the values in its environment (see the fail-closed notes above).
func runRedeemed(storeDir string, st *store.Store, rest []string) error {
	opts, err := parseRunArgs(rest, os.Getenv("KEYSMITH_SESSION"))
	if err != nil {
		return err
	}
	cmdArgs, templates, sid := opts.Command, opts.Envs, opts.Session

	if len(cmdArgs) == 0 {
		return fmt.Errorf("run: no command given\n\n%s", runUsage)
	}
	if len(templates) == 0 {
		return fmt.Errorf("run: at least one --env KEY=<template> is required\n\n%s", runUsage)
	}
	if err := checkNoTokensInCommand(cmdArgs); err != nil {
		return err
	}

	needsSession := false
	for _, tpl := range templates {
		if redeem.HasToken(tpl) {
			needsSession = true
			break
		}
	}

	sessions := redeem.NewSessions(storeDir)
	resolver := redeem.NewResolver(sessions, st)
	var sess *redeem.Session
	if needsSession {
		var err error
		if sid != "" {
			sess, err = sessions.LoadPrefix(sid)
		} else {
			sess, err = sessions.Current()
		}
		if err != nil {
			return err
		}
	}

	childEnv := make([]string, 0, len(templates))
	var redeemed []string
	for _, tpl := range templates {
		key, template, err := parseEnvTemplate(tpl)
		if err != nil {
			return err
		}
		value, names, err := resolver.Resolve(template)
		if err != nil {
			// Fail closed: nothing is exported, nothing is executed.
			return fmt.Errorf("run: %w", err)
		}
		childEnv = append(childEnv, key+"="+value)
		redeemed = append(redeemed, names...)
	}

	if len(redeemed) > 0 {
		// Audited before the child starts, and the audit is part of the
		// fail-closed path: no record, no execution.
		rec := redeem.AuditRecord{
			Session: sess.ID[:8],
			Keys:    redeem.SortedUnique(redeemed),
			Command: filepath.Base(cmdArgs[0]),
			Argc:    len(cmdArgs) - 1,
			PID:     os.Getpid(),
		}
		if err := redeem.AppendAudit(storeDir, rec); err != nil {
			return fmt.Errorf("run: cannot write the redemption audit log: %w", err)
		}
		fmt.Fprintf(os.Stderr, "keysmith: redeemed %s for %s\n",
			strings.Join(rec.Keys, ","), rec.Command)
	}

	child := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = mergeEnv(envWithout(os.Environ(), "KEYSMITH_SESSION"), childEnv)

	if err := child.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("run: %w", err)
	}
	return nil
}

// envWithout drops every entry for the named variable, so a redeemed session
// id never reaches the child through the inherited environment.
func envWithout(env []string, name string) []string {
	out := env[:0:0]
	for _, e := range env {
		if strings.HasPrefix(e, name+"=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// mergeEnv returns base without any entry whose name is set by overrides,
// followed by the overrides. execve receives the slice unchanged, so keeping a
// duplicate entry would leave the stale parent value in the child's environ.
func mergeEnv(base, overrides []string) []string {
	replaced := make(map[string]bool, len(overrides))
	for _, o := range overrides {
		if i := strings.Index(o, "="); i > 0 {
			replaced[o[:i]] = true
		}
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, e := range base {
		if i := strings.Index(e, "="); i > 0 && replaced[e[:i]] {
			continue
		}
		out = append(out, e)
	}
	return append(out, overrides...)
}

func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func defaultStoreDir() string {
	// KEYSMITH_STORE takes precedence; legacy SECRET_MCP_STORE still works.
	if v := os.Getenv("KEYSMITH_STORE"); v != "" {
		return v
	}
	if v := os.Getenv("SECRET_MCP_STORE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".keysmith"
	}
	return filepath.Join(home, ".keysmith")
}
