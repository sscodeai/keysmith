package mask

import "testing"

func TestKeyNameIsSensitive(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"API_SECRET", true},
		{"DATABASE_URL", false},          // URL is plain-config last word
		{"GITHUB_TOKEN", true},
		{"AUTH_TOKEN", true},
		{"DB_PASSWORD", true},
		{"AWS_ACCESS_KEY_ID", true},
		{"PORT", false},
		{"DEBUG", false},
		{"BETTER_AUTH_URL", false},       // URL last word overrides AUTH
		{"SIGNING_SECRET", true},
		{"NEO4J_URL", false},             // URL last word
		{"MY_CREDENTIAL_FILE", true},     // CREDENTIAL anywhere
	}
	for _, c := range cases {
		if got := KeyNameIsSensitive(c.key); got != c.want {
			t.Errorf("KeyNameIsSensitive(%q) = %v, want %v", c.key, got, c.want)
		}
	}
}

func TestValueLooksSecret(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"sk-1234567890abcdef", true},        // sk- prefix
		{"ghp_1234567890abcdefghij", true},   // GitHub PAT
		{"glpat-abcdef1234567890", true},     // GitLab PAT
		{"xoxb-1234567890-abcdef", true},     // Slack
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0", true}, // JWT
		{"AKIAIOSFODNN7EXAMPLE", true},       // AWS access key
		{"604800", false},                    // pure numeric (timeout)
		{"hello", false},                     // short, not secret
		{"myapp-demo-snapshot", false},       // structured, segments short
		{"oss-cn-beijing.aliyuncs.com", false}, // hostname
		{"abcdefghijklmnopqrstuvwxyz", false},  // all letters, entropy low
		{"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6", true}, // mixed 36 chars
	}
	for _, c := range cases {
		if got := ValueLooksSecret(c.val); got != c.want {
			t.Errorf("ValueLooksSecret(%q) = %v, want %v", c.val, got, c.want)
		}
	}
}

func TestMask(t *testing.T) {
	cases := []struct {
		val  string
		want string
	}{
		{"sk-1234567890abcdef", "sk******ef"},
		{"hello", "hello"},                       // not secret
		{"604800", "604800"},                     // not secret
		{"x", "x"},                               // single char, not secret
	}
	for _, c := range cases {
		if got := Mask(c.val); got != c.want {
			t.Errorf("Mask(%q) = %q, want %q", c.val, got, c.want)
		}
	}
}

func TestMaskURL(t *testing.T) {
	cases := []struct {
		val  string
		want string
	}{
		{
			"postgres://user:supersecretpass123@db.example.com:5432/mydb",
			"postgres://user:su******23@db.example.com:5432/mydb",
		},
		{
			"https://hooks.slack.com/services/T01ABCDEFGH/B02JKLMNOPQ/x9tokenvalue123456",
			"https://hooks.slack.com/services/T01ABCDEFGH/B02JKLMNOPQ/x9******56",
		},
		{
			"neo4j://neo4j:password12345@102.10.101.125:7687",
			"neo4j://neo4j:pa******45@102.10.101.125:7687",
		},
	}
	for _, c := range cases {
		got := MaskURL(c.val)
		if got != c.want {
			t.Errorf("MaskURL(%q) = %q, want %q", c.val, got, c.want)
		}
		// Assert no full secret remains (only masked segments).
		if len(got) >= 20 {
			// The masked form must differ from the original.
			if got == c.val {
				t.Errorf("MaskURL(%q) did not change anything", c.val)
			}
		}
	}
}

func TestMaskNeverLeaksPlaintextForSecrets(t *testing.T) {
	secrets := []string{
		"sk-abcdefghijklmnopqrstuvwxyz123456",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
		"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
		"postgres://u:SuperSecretPass123456@h:5432/db",
	}
	for _, s := range secrets {
		masked := Mask(s)
		if masked == s {
			t.Errorf("Mask(%q) returned original — plaintext leaked", s)
		}
		if len(masked) < 4 && len(s) > 4 {
			t.Errorf("Mask(%q) = %q too short", s, masked)
		}
	}
}
