// Package vault implements a HashiCorp Vault backend for keysmith,
// providing dynamic short-TTL secrets: a leaked credential expires on its
// own (lease TTL), which is the strongest "leak harmless" guarantee.
//
// Two modes:
//   - KV v2: static secrets stored in Vault KV (equivalent to the local
//     age store, but centralised and with Vault's own access control).
//   - Database dynamic credentials: Vault generates short-lived DB
//     username/password on demand (default TTL 1h) — perfect for agents
//     that need DB access without long-lived credentials.
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client is a minimal Vault HTTP API client. It deliberately implements only
// the endpoints keysmith needs (KV read/write, database creds, lease info)
// to keep dependencies minimal — no huge SDK.
type Client struct {
	addr     string // e.g. http://127.0.0.1:8200
	token    string
	http     *http.Client
	kvPrefix string // e.g. "secret/data" (KV v2) or "secret" (KV v1)
}

// Credentials for a dynamic database secret.
type DBCreds struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	LeaseID   string    `json:"lease_id"`
	LeaseTTL  int       `json:"lease_ttl"` // seconds
	Renewable bool      `json:"renewable"`
	ExpiresAt time.Time `json:"-"`
}

// NewClient creates a Vault client. addr is like "http://127.0.0.1:8200".
func NewClient(addr, token, kvPrefix string) *Client {
	if kvPrefix == "" {
		kvPrefix = "secret"
	}
	return &Client{
		addr:     strings.TrimSuffix(addr, "/"),
		token:    token,
		http:     &http.Client{Timeout: 10 * time.Second},
		kvPrefix: strings.TrimSuffix(kvPrefix, "/"),
	}
}

// Health checks Vault reachability.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr+"/v1/sys/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vault unreachable: %w", err)
	}
	defer resp.Body.Close()
	// 200 = initialized+unsealed, 501 = not initialized, 503 = sealed.
	if resp.StatusCode == 200 {
		return nil
	}
	return fmt.Errorf("vault health status %d", resp.StatusCode)
}

// SetKV stores a static secret under key in the KV store.
func (c *Client) SetKV(ctx context.Context, key, value string) error {
	// KV v2 path: {prefix}/data/{key}; body {"data":{"value":...}}
	body, _ := json.Marshal(map[string]any{"data": map[string]string{"value": value}})
	path := c.kvPrefix + "/data/" + key
	return c.do(ctx, http.MethodPost, path, body)
}

// GetKV reads a static secret. Returns masked form if masked is true.
func (c *Client) GetKV(ctx context.Context, key string) (string, error) {
	path := c.kvPrefix + "/data/" + key
	var out struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return "", err
	}
	return out.Data.Data["value"], nil
}

// DeleteKV removes a static secret.
func (c *Client) DeleteKV(ctx context.Context, key string) error {
	path := c.kvPrefix + "/data/" + key
	return c.do(ctx, http.MethodDelete, path, nil)
}

// ListKV lists keys under the KV prefix. Returns map key → masked value.
func (c *Client) ListKV(ctx context.Context) (map[string]string, error) {
	// List keys: LIST {prefix}/metadata/ (Vault list op uses LIST method)
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	path := c.kvPrefix + "/metadata/"
	if err := c.doJSON(ctx, "LIST", path, nil, &out); err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, k := range out.Data.Keys {
		v, err := c.GetKV(ctx, k)
		if err != nil {
			continue
		}
		result[k] = maskValue(v)
	}
	return result, nil
}

// GetDBCreds requests dynamic database credentials from a Vault DB role.
// The returned creds have a short TTL (lease) — they expire on their own,
// so a leaked credential is harmless.
func (c *Client) GetDBCreds(ctx context.Context, role string) (*DBCreds, error) {
	path := "database/creds/" + role
	var out struct {
		Data struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"data"`
		LeaseID       string `json:"lease_id"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &DBCreds{
		Username:  out.Data.Username,
		Password:  out.Data.Password,
		LeaseID:   out.LeaseID,
		LeaseTTL:  out.LeaseDuration,
		Renewable: out.Renewable,
		ExpiresAt: time.Now().Add(time.Duration(out.LeaseDuration) * time.Second),
	}, nil
}

// RenewLease extends a dynamic credential's lease.
func (c *Client) RenewLease(ctx context.Context, leaseID string, increment int) error {
	body, _ := json.Marshal(map[string]any{"lease_id": leaseID, "increment": increment})
	return c.do(ctx, http.MethodPut, "sys/leases/renew", body)
}

// RevokeLease immediately revokes a dynamic credential (kills it early).
func (c *Client) RevokeLease(ctx context.Context, leaseID string) error {
	body, _ := json.Marshal(map[string]any{"lease_id": leaseID})
	return c.do(ctx, http.MethodPut, "sys/leases/revoke", body)
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) error {
	return c.doJSON(ctx, method, path, body, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body []byte, out any) error {
	var reader *strings.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	} else {
		reader = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+"/v1/"+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf := make([]byte, 200)
		n, _ := resp.Body.Read(buf)
		return fmt.Errorf("vault %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(buf[:n])))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// maskValue is a tiny inline masker for Vault values (reuses mask pkg when
// wired, but kept standalone to avoid import cycle).
func maskValue(v string) string {
	if v == "" {
		return ""
	}
	if len(v) <= 4 {
		return v[:1] + "***"
	}
	return v[:2] + "******" + v[len(v)-2:]
}
