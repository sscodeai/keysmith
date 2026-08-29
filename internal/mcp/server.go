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
	mcp   *mcp.Server
}

// NewServer creates an MCP server backed by the given store.
func NewServer(st *store.Store) (*Server, error) {
	s := &Server{store: st}
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "keysmith",
		Version: "0.1.0",
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
		Description: "Read a single secret's MASKED value (use --unsafe only if you must see plaintext)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args getArgs) (*mcp.CallToolResult, any, error) {
		v, err := st.Get(args.Key)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, nil, fmt.Errorf("key %q not found", args.Key)
			}
			return nil, nil, fmt.Errorf("get %q: %w", args.Key, err)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: mask.Mask(v)}}}, nil, nil
	})

	// put: set a secret. Value is read from a temp file path arg, so the
	// plaintext never appears in the tool call transcript.
	type putArgs struct {
		Key       string `json:"key" jsonschema:"the secret key name"`
		ValueFile string `json:"value_file" jsonschema:"path to a file containing the value (keeps plaintext out of the transcript)"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "put",
		Description: "Store a secret. Pass value_file (a path to a file containing the value) to avoid putting plaintext in the transcript.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args putArgs) (*mcp.CallToolResult, any, error) {
		if args.Key == "" {
			return nil, nil, errors.New("key is required")
		}
		val, err := readValueFile(args.ValueFile)
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
		Description: "Generate a new random secret for key and store it. Returns the masked value (plaintext via --unsafe only).",
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

// readValueFile reads a secret value from a file (single line, trailing newline
// stripped). The file is removed after reading to avoid leaving plaintext.
func readValueFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("value_file is required (write the value to a temp file first)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read value file: %w", err)
	}
	val := strings.TrimSuffix(string(b), "\n")
	val = strings.TrimSuffix(val, "\r")
	// Best-effort cleanup: remove the temp file so plaintext doesn't linger.
	abs, aerr := filepath.Abs(path)
	if aerr == nil {
		_ = os.Remove(abs)
	}
	return val, nil
}
