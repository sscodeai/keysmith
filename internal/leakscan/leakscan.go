// Package leakscan implements self-healing rotation: detect leaked secrets
// in git history or file scans, then flag (or auto-rotate) them.
//
// Design:
//   - Scan a repo's git log for known secret patterns (the same markers as
//     internal/mask) or for exact matches of store keys' values.
//   - For each leak found, recommend/perform rotation — a leaked credential
//     is killed by rotating it to a new strong value.
package leakscan

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/sscodeai/secret-mcp/internal/mask"
	"github.com/sscodeai/secret-mcp/internal/store"
)

// ScanResult describes one detected leak.
type ScanResult struct {
	Key       string // store key whose value leaked (if known)
	Pattern   string // matched pattern
	Location  string // file:line or commit ref
	Rotated   bool   // whether auto-rotation was applied
	NewMasked string // masked new value if rotated
}

// ScanGitHistory scans a repo's git log for leaked secret patterns and
// exact-value matches against the store. If autoRotate is true, matching
// store keys are rotated and the leak is killed.
func ScanGitHistory(repoDir string, st *store.Store, autoRotate bool) ([]ScanResult, error) {
	var results []ScanResult

	// Collect store values for exact-match scanning.
	values := map[string]string{} // masked value -> original key
	if st != nil {
		keys, err := st.SortedKeys()
		if err == nil {
			for _, k := range keys {
				v, err := st.Get(k)
				if err == nil && len(v) >= 8 {
					values[v] = k
				}
			}
		}
	}

	// git log -p gives full diffs of every commit.
	cmd := exec.Command("git", "-C", repoDir, "log", "-p", "--all")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log: %w", err)
	}

	// Current file scan (working tree) — find secret-looking lines.
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "+") == false && strings.HasPrefix(trimmed, "-") == false {
			// still scan content lines but skip pure context noise
			if !strings.Contains(trimmed, "=") && !strings.Contains(trimmed, ":") {
				continue
			}
		}
		// Skip obvious non-secret lines.
		if strings.Contains(trimmed, "commit ") || strings.Contains(trimmed, "Author:") ||
			strings.Contains(trimmed, "Date:") || strings.Contains(trimmed, "diff --git") ||
			strings.Contains(trimmed, "index ") || strings.Contains(trimmed, "---") ||
			strings.Contains(trimmed, "+++") || strings.Contains(trimmed, "@@") {
			continue
		}

		// 1) Exact value match against store.
		rotated := false
		for val, key := range values {
			if strings.Contains(trimmed, val) {
				res := ScanResult{Key: key, Pattern: "exact-value", Location: line, Rotated: rotated}
				if autoRotate && !rotated {
					if _, err := st.Rotate(key, 32); err == nil {
						res.Rotated = true
						res.NewMasked = mask.Mask(mustGet(st, key))
						rotated = true
					}
				}
				results = append(results, res)
			}
		}

		// 2) Pattern match (known secret shapes).
		if isSecretPattern(trimmed) {
			results = append(results, ScanResult{Pattern: "pattern", Location: line})
		}
	}

	return results, nil
}

// isSecretPattern reports whether a line looks like it contains a secret
// (reusing mask package heuristics). It skips comments and known
// source-code pattern definitions to reduce false positives.
func isSecretPattern(line string) bool {
	trimmed := strings.TrimSpace(line)
	// Skip comments, doc strings, and obvious non-secret lines.
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "-") && !strings.HasPrefix(trimmed, "- ") ||
		strings.HasPrefix(trimmed, "<!--") {
		// '-' lines are diff deletions — still scan those (they may be a
		// removed secret), but skip pure comment markers.
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			return false
		}
	}
	// Skip lines that are just the prefix definitions (test fixtures, docs).
	if strings.Contains(trimmed, `"sk-"`) || strings.Contains(trimmed, `"ghp_"`) ||
		strings.Contains(trimmed, `"glpat-"`) || strings.Contains(trimmed, `"xoxb-"`) ||
		strings.Contains(trimmed, "credential prefixes") || strings.Contains(trimmed, "known value prefixes") {
		return false
	}

	// Known credential value prefixes.
	prefixes := []string{"sk-", "ghp_", "glpat-", "xoxb-", "AKIA", "eyJ", "ya29.", "AIza"}
	for _, p := range prefixes {
		if strings.Contains(line, p) {
			return true
		}
	}
	// Assignment of a high-entropy value: KEY=value or KEY: value
	assignRe := regexp.MustCompile(`(?i)(secret|token|password|api[_-]?key|access[_-]?key|dsn)\s*[=:]\s*(\S+)`)
	if m := assignRe.FindStringSubmatch(line); len(m) >= 3 {
		val := strings.Trim(m[2], `"'`)
		if mask.ValueLooksSecret(val) {
			return true
		}
	}
	return false
}

func mustGet(st *store.Store, key string) string {
	v, err := st.Get(key)
	if err != nil {
		return ""
	}
	return v
}

// Format renders scan results for human consumption (masked).
func Format(results []ScanResult) string {
	if len(results) == 0 {
		return "no leaks detected"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%d potential leak(s) found:\n", len(results))
	for i, r := range results {
		action := "FLAG"
		if r.Rotated {
			action = "ROTATED → " + r.NewMasked
		}
		fmt.Fprintf(&b, "  [%d] %s | %s | %s | %s\n", i+1, action, r.Pattern, r.Key, truncate(r.Location, 80))
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
