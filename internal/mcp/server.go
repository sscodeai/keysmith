// Package mcp wires the secret store into a Model Context Protocol server.
//
// Security model:
//   - resources expose ONLY masked values (safe for agent context)
//   - tools provide controlled operations; plaintext values NEVER appear in
//     tool RESULTS (only in the store, decrypted in-memory transiently)
//   - put reads the value from stdin semantics via a temp-file argument, not
//     from the tool argument itself (keeps plaintext out of transcript)
package mcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sscodeai/keysmith/internal/mask"
	"github.com/sscodeai/keysmith/internal/store"
)

// Server wraps a secret store as an MCP server.
type Server struct {
	store *store.Store
	inbox string
	mcp   *mcp.Server
}

// InboxDirName is the directory, next to the encrypted store, where `put` reads
// value files from. Agents are told about it (`keysmith inbox`); anything
// outside it is refused by readValueFile.
const InboxDirName = "inbox"

// NewServer creates an MCP server backed by the given store. version is what
// clients see as serverInfo.version; an empty value is reported as "dev".
//
// The inbox directory is created with 0700 because `put` will only read (and
// then delete) value files inside it: the tool argument is agent-controlled, so
// an unrestricted path would be an arbitrary-file read and unlink primitive.
func NewServer(st *store.Store, version string) (*Server, error) {
	if version == "" {
		version = "dev"
	}
	inbox := filepath.Join(st.Dir(), InboxDirName)
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		return nil, fmt.Errorf("create inbox: %w", err)
	}
	s := &Server{store: st, inbox: inbox}
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "keysmith",
		Version: version,
	}, nil)

	// --- Resources: masked secret views (safe for agent context) ---
	srv.AddResource(&mcp.Resource{
		Name:        "secrets",
		Description: "Masked view of all secrets (values are redacted)",
		URI:         "secret://secrets",
		MIMEType:    "text/plain",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		items, err := st.List()
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		keys := make([]string, 0, len(items))
		for k := range items {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(items[k])
			b.WriteString("\n")
		}
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{
					URI:      "secret://secrets",
					MIMEType: "text/plain",
					Text:     b.String(),
				},
			},
		}, nil
	})

	// --- Tools ---

	// list: masked view of all keys
	type listArgs struct{}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list",
		Description: "List all secret keys with MASKED values (plaintext never shown)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args listArgs) (*mcp.CallToolResult, any, error) {
		items, err := st.List()
		if err != nil {
			return nil, nil, fmt.Errorf("list: %w", err)
		}
		keys := make([]string, 0, len(items))
		for k := range items {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(items[k])
			b.WriteString("\n")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, nil, nil
	})

	// get: read a single masked value
	type getArgs struct {
		Key string `json:"key" jsonschema:"the secret key name"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get",
		Description: "Read a single secret's MASKED value. MCP never returns plaintext — to use a value without reading it, redeem it with `keysmith run` on the host.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getArgs) (*mcp.CallToolResult, any, error) {
		v, err := st.Get(args.Key)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, nil, fmt.Errorf("key %q not found", args.Key)
			}
			return nil, nil, fmt.Errorf("get %q: %w", args.Key, err)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: mask.MaskKey(args.Key, v)}}}, nil, nil
	})

	// put: set a secret. Value is read from a temp file path arg, so the
	// plaintext never appears in the tool call transcript.
	type putArgs struct {
		Key       string `json:"key" jsonschema:"the secret key name"`
		ValueFile string `json:"value_file" jsonschema:"path to a file inside the keysmith inbox containing the value (keeps plaintext out of the transcript)"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name: "put",
		Description: "Store a secret. Write the value to a file inside the keysmith inbox " +
			"(run `keysmith inbox` for the path), then pass that path as value_file: paths " +
			"outside the inbox are refused, and the file is deleted after it is read.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args putArgs) (*mcp.CallToolResult, any, error) {
		if args.Key == "" {
			return nil, nil, errors.New("key is required")
		}
		val, err := readValueFile(s.inbox, args.ValueFile)
		if err != nil {
			return nil, nil, err
		}
		if err := st.Set(args.Key, val); err != nil {
			return nil, nil, fmt.Errorf("set %q: %w", args.Key, err)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("stored %s (masked: %s)", args.Key, mask.Mask(val))}}}, nil, nil
	})

	// rotate: generate a new strong secret for key, return masked
	type rotateArgs struct {
		Key    string `json:"key" jsonschema:"the secret key name"`
		Length int    `json:"length,omitempty" jsonschema:"desired length (default 32)"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "rotate",
		Description: "Generate a new random secret for key and store it. Returns the masked value only; plaintext is never returned over MCP.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args rotateArgs) (*mcp.CallToolResult, any, error) {
		if args.Key == "" {
			return nil, nil, errors.New("key is required")
		}
		length := args.Length
		if length == 0 {
			length = 32
		}
		masked, err := st.Rotate(args.Key, length)
		if err != nil {
			return nil, nil, fmt.Errorf("rotate %q: %w", args.Key, err)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("rotated %s -> %s", args.Key, masked)}}}, nil, nil
	})

	// delete: remove a key
	type deleteArgs struct {
		Key string `json:"key" jsonschema:"the secret key name"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delete",
		Description: "Delete a secret key",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args deleteArgs) (*mcp.CallToolResult, any, error) {
		if args.Key == "" {
			return nil, nil, errors.New("key is required")
		}
		if err := st.Delete(args.Key); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, nil, fmt.Errorf("key %q not found", args.Key)
			}
			return nil, nil, fmt.Errorf("delete %q: %w", args.Key, err)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("deleted %s", args.Key)}}}, nil, nil
	})

	s.mcp = srv
	return s, nil
}

// Run starts the MCP server on stdio transport.
func (s *Server) Run(ctx context.Context) error {
	return s.mcp.Run(ctx, &mcp.StdioTransport{})
}

// Handler returns the underlying SDK server, for HTTP/SSE serving.
func (s *Server) Handler() *mcp.Server {
	return s.mcp
}

// readValueFile reads a secret value from a file inside inbox (single line,
// trailing newline stripped) and removes it after reading, so plaintext does
// not linger. Paths outside the inbox are refused: the MCP caller chooses this
// path, and reading + unlinking an arbitrary file would be a destructive
// primitive (for example value_file: "~/.ssh/id_ed25519").
func readValueFile(inbox, path string) (string, error) {
	inside, err := resolveInside(inbox, path)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(inside)
	if err != nil {
		return "", fmt.Errorf("read value file: %w", err)
	}
	val := strings.TrimSuffix(string(b), "\n")
	val = strings.TrimSuffix(val, "\r")
	// Remove the file now that the value is in memory.
	_ = os.Remove(inside)
	return val, nil
}

// resolveInside returns path if it resolves, after following symlinks, to a
// regular file inside dir. Anything else — a relative escape, an absolute path
// elsewhere, or a symlink pointing out of dir — is refused.
func resolveInside(dir, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("value_file is required: write the value to %s and pass that path", dir)
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("resolve inbox: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve value file: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("read value file: %w", err)
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == "." || rel == ".." ||
		filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("value_file must be inside the keysmith inbox (%s); run `keysmith inbox` for the path", dir)
	}
	return resolved, nil
}
