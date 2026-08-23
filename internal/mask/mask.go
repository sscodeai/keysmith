// Package mask implements secret masking rules for .env values.
//
// Design: a value is masked when any of these match:
//   - key name contains SECRET/TOKEN/PASSWORD/API_KEY/ACCESS_KEY/PRIVATE/CREDENTIAL/AUTH/SALT/SIGNING/DSN (case-insensitive),
//     unless the key's last word marks plain config (URL/URI/ENDPOINT/HOST/PORT/DOMAIN/PATH/NAME/TELEMETRY...)
//   - value prefix matches known credential formats: sk-, ghp_, glpat-, xoxb-, AKIA..., JWT (eyJ...)
//   - value contains an unbroken alphanumeric run of >=20 chars mixing letters+digits with Shannon entropy >=3.5
//
// Pure-numeric values (timeouts, sizes, retry counts) are NEVER treated as secrets.
// URL-shaped values are masked per-segment: userinfo password always masked,
// random-looking runs in path/query masked, scheme/user/host/port stay clear.
//
// Masked form keeps first and last 2 chars: sk******ij
package mask

import (
	"math"
	"regexp"
	"strings"
)

// Sensitive key-name markers (case-insensitive substring match).
var sensitiveKeyPatterns = []string{
	"SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "APIKEY",
	"ACCESS_KEY", "PRIVATE", "CREDENTIAL", "AUTH", "SALT",
	"SIGNING", "DSN", "PWD", "PASS",
}

// Plain-config key-name markers that override sensitive patterns when they are
// the LAST word of the key (e.g. BETTER_AUTH_URL is not a secret by name alone).
var plainConfigLastWords = []string{
	"URL", "URI", "ENDPOINT", "HOST", "PORT", "DOMAIN", "PATH",
	"NAME", "TELEMETRY", "ENABLED", "MODE", "LEVEL", "REGION",
}

// Known credential value prefixes.
var credentialPrefixes = []string{
	"sk-", "pk-", "ghp_", "gho_", "ghu_", "glpat-", "xoxb-", "xoxp-",
	"AKIA", "ASIA", "eyJ", "ya29.", "AIza", "SG.", "runc-", "npm_",
}

var urlSchemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)
var alnumRunRe = regexp.MustCompile(`[A-Za-z0-9]{20,}`)

// KeyNameIsSensitive reports whether a key name should be treated as a secret
// by name alone.
func KeyNameIsSensitive(key string) bool {
	upper := strings.ToUpper(key)
	// Plain-config last-word override.
	words := strings.FieldsFunc(upper, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	if len(words) > 0 {
		last := words[len(words)-1]
		for _, p := range plainConfigLastWords {
			if last == p {
				return false
			}
		}
	}
	for _, p := range sensitiveKeyPatterns {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

// ValueLooksSecret reports whether a value itself looks like a credential.
// Pure-numeric values are never secrets.
func ValueLooksSecret(value string) bool {
	if value == "" || isPureNumeric(value) {
		return false
	}
	// URL-shaped: secrets live in specific segments, handled by URL masking.
	if urlSchemeRe.MatchString(value) {
		return false // handled by MaskURL-style masking
	}
	// Known credential prefixes (case-sensitive — sk-, ghp_, etc. are always
	// lowercase in practice).
	for _, p := range credentialPrefixes {
		if strings.HasPrefix(value, p) {
			return true
		}
	}
	// Random-looking alphanumeric run >= 20 chars mixing letters AND digits,
	// with entropy >= 3.5. Pure-letter runs (dictionary-ish) are NOT secrets.
	for _, run := range alnumRunRe.FindAllString(value, -1) {
		if len(run) >= 20 && hasLetterAndDigit(run) && entropy(run) >= 3.5 {
			return true
		}
	}
	return false
}

// hasLetterAndDigit reports whether a run mixes both letters and digits.
func hasLetterAndDigit(s string) bool {
	var letter, digit bool
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			letter = true
		}
		if c >= '0' && c <= '9' {
			digit = true
		}
	}
	return letter && digit
}

// Mask returns the masked form of a value. If the value is not secret, it is
// returned unchanged. If it is secret, first/last 2 chars are kept with
// stars in between (short values are fully masked except first 2 chars).
// URL-shaped values always go through URL masking (password/userinfo segments
// are masked even if the value itself has no high-entropy run).
func Mask(value string) string {
	if value == "" {
		return ""
	}
	if urlSchemeRe.MatchString(value) {
		return MaskURL(value)
	}
	if !ValueLooksSecret(value) {
		return value
	}
	return maskPlain(value)
}

// MaskURL masks a URL-shaped value per segment: userinfo password always
// masked, random-looking runs in path/query masked, scheme/user/host/port stay
// clear.
func MaskURL(raw string) string {
	// Find scheme separator.
	idx := strings.Index(raw, "://")
	if idx < 0 {
		return maskPlain(raw)
	}
	scheme := raw[:idx+3]
	rest := raw[idx+3:]

	// Split userinfo@host:port/path?query
	atIdx := strings.Index(rest, "@")
	var userinfo, hostport string
	if atIdx >= 0 {
		userinfo = rest[:atIdx]
		hostport = rest[atIdx+1:]
	} else {
		hostport = rest
	}

	var maskedUserinfo string
	if userinfo != "" {
		// user:password — always mask password, keep user.
		if colon := strings.Index(userinfo, ":"); colon >= 0 {
			user := userinfo[:colon]
			pass := userinfo[colon+1:]
			maskedUserinfo = user + ":" + maskPlain(pass)
		} else {
			maskedUserinfo = maskPlain(userinfo)
		}
		maskedUserinfo += "@"
	}

	// Path/query: mask random-looking runs.
	slashIdx := strings.Index(hostport, "/")
	var host, pathq string
	if slashIdx >= 0 {
		host = hostport[:slashIdx]
		pathq = hostport[slashIdx:]
	} else {
		host = hostport
		pathq = ""
	}

	// Mask random-looking runs in path/query. URL path segments are more likely
	// to be tokens (webhook IDs, API keys), so use a lower threshold (16) here
	// than for plain values (20). The regexp must match runs >= 16 chars.
	urlRunRe := regexp.MustCompile(`[A-Za-z0-9]{16,}`)
	maskedPathQ := urlRunRe.ReplaceAllStringFunc(pathq, func(run string) string {
		if len(run) >= 16 && entropy(run) >= 3.5 {
			return maskPlain(run)
		}
		return run
	})

	return scheme + maskedUserinfo + host + maskedPathQ
}

// maskPlain masks a plain string keeping first and last 2 chars.
func maskPlain(s string) string {
	if len(s) <= 4 {
		return s[:min(1, len(s))] + "***" // very short: keep first char
	}
	return s[:2] + "******" + s[len(s)-2:]
}

func isPureNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// entropy computes Shannon entropy (bits per char) of a string.
func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	var e float64
	n := float64(len(s))
	for _, f := range freq {
		p := float64(f) / n
		e -= p * math.Log2(p)
	}
	return e
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
