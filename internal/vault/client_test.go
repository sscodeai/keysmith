package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMockVault spins up an httptest server mimicking the Vault HTTP API
// enough for KV + health + db creds tests.
func newMockVault(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()
	store := map[string]string{"existing": "sk-existing-value-1234567890"}

	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"initialized":true,"sealed":false}`))
	})
	mux.HandleFunc("/v1/secret/data/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
		switch r.Method {
		case http.MethodGet:
			if v, ok := store[key]; ok {
				json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{"data": map[string]string{"value": v}},
				})
			} else {
				w.WriteHeader(404)
			}
		case http.MethodPost:
			var body struct {
				Data map[string]string `json:"data"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			store[key] = body.Data["value"]
			w.WriteHeader(200)
			w.Write([]byte(`{"data":{"ok":true}}`))
		}
	})
	mux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "LIST" {
			keys := make([]string, 0, len(store))
			for k := range store {
				keys = append(keys, k)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"keys": keys},
			})
		}
	})
	mux.HandleFunc("/v1/database/creds/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{
				"data":         map[string]string{"username": "v-token-role-abc", "password": "generated-pass-xyz"},
				"lease_id":     "database/creds/app-role/xyz",
				"lease_duration": 3600,
				"renewable":    true,
			})
		}
	})

	srv := httptest.NewServer(mux)
	return srv, NewClient(srv.URL, "test-token", "secret")
}

func TestHealth(t *testing.T) {
	srv, c := newMockVault(t)
	defer srv.Close()
	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestSetGetKV(t *testing.T) {
	srv, c := newMockVault(t)
	defer srv.Close()
	ctx := context.Background()
	if err := c.SetKV(ctx, "newkey", "sk-new-value-1234567890"); err != nil {
		t.Fatalf("SetKV: %v", err)
	}
	got, err := c.GetKV(ctx, "newkey")
	if err != nil {
		t.Fatalf("GetKV: %v", err)
	}
	if got != "sk-new-value-1234567890" {
		t.Errorf("GetKV = %q, want stored value", got)
	}
}

func TestListKV(t *testing.T) {
	srv, c := newMockVault(t)
	defer srv.Close()
	items, err := c.ListKV(context.Background())
	if err != nil {
		t.Fatalf("ListKV: %v", err)
	}
	if _, ok := items["existing"]; !ok {
		t.Errorf("ListKV missing 'existing', got %v", items)
	}
	// Masked value must not contain the full secret.
	if strings.Contains(items["existing"], "sk-existing-value-1234567890") {
		t.Error("ListKV leaked plaintext")
	}
}

func TestGetDBCreds(t *testing.T) {
	srv, c := newMockVault(t)
	defer srv.Close()
	creds, err := c.GetDBCreds(context.Background(), "app-role")
	if err != nil {
		t.Fatalf("GetDBCreds: %v", err)
	}
	if creds.Username != "v-token-role-abc" {
		t.Errorf("username = %q", creds.Username)
	}
	if creds.Password == "" {
		t.Error("empty password")
	}
	if creds.LeaseTTL != 3600 {
		t.Errorf("LeaseTTL = %d, want 3600", creds.LeaseTTL)
	}
	if !creds.Renewable {
		t.Error("expected renewable")
	}
	if creds.ExpiresAt.IsZero() {
		t.Error("ExpiresAt not set")
	}
}
