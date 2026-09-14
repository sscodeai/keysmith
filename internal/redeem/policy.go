package redeem

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Binding restricts where a token may be redeemed. It is recorded at issue time
// and enforced by `keysmith run --target`. A zero Binding means "any command",
// which is the default and is reported to the user at issue time.
type Binding struct {
	Hosts        []string `json:"hosts,omitempty"`         // exact host, or ".example.test" for a suffix
	PathPrefixes []string `json:"path_prefixes,omitempty"` // "/v1/" — the target path must start with one of these
	Headers      []string `json:"headers,omitempty"`       // header names that must appear in the command
}

// IsZero reports whether the binding restricts anything at all.
func (b Binding) IsZero() bool {
	return len(b.Hosts) == 0 && len(b.PathPrefixes) == 0 && len(b.Headers) == 0
}

// String renders the binding for status output.
func (b Binding) String() string {
	if b.IsZero() {
		return "unbound (any command)"
	}
	parts := make([]string, 0, 3)
	if len(b.Hosts) > 0 {
		parts = append(parts, "hosts="+strings.Join(b.Hosts, "|"))
	}
	if len(b.PathPrefixes) > 0 {
		parts = append(parts, "paths="+strings.Join(b.PathPrefixes, "|"))
	}
	if len(b.Headers) > 0 {
		parts = append(parts, "headers="+strings.Join(b.Headers, "|"))
	}
	return strings.Join(parts, " ")
}

// Target is the destination a command declares with `--target`.
type Target struct {
	Host   string // lowercase, no port
	Port   string // may be empty
	Path   string // path only, never a query or fragment
	Secure bool   // true for https
}

// ParseTarget parses a --target URL. Query strings and fragments are rejected
// rather than ignored, because they are where a hidden destination would live.
func ParseTarget(raw string) (*Target, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("empty target URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("unparsable target URL: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("target %q uses http: plain http is only allowed for loopback addresses", u.Host)
		}
	default:
		return nil, fmt.Errorf("target %q must use https (or http on loopback)", raw)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("target %q has no host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("target must not carry a query string or fragment")
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return &Target{
		Host:   strings.ToLower(u.Hostname()),
		Port:   u.Port(),
		Path:   path,
		Secure: u.Scheme == "https",
	}, nil
}

func isLoopback(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// hostAllowed reports whether host matches one of the allowed entries. An entry
// beginning with "." matches that domain and its subdomains, and never a
// look-alike such as "evil-example.test".
func hostAllowed(host string, allowed []string) bool {
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, ".") {
			if strings.HasSuffix(host, a) {
				return true
			}
			continue
		}
		if host == a {
			return true
		}
	}
	return false
}

// Check evaluates the binding against the declared target and against the text
// of the command that will receive the value (its --env templates and its
// arguments). A zero binding allows anything.
func (b Binding) Check(t *Target, surface string) error {
	if b.IsZero() {
		return nil
	}
	if t == nil {
		return errors.New("this token is bound to a target: pass --target <url>")
	}
	if len(b.Hosts) > 0 && !hostAllowed(t.Host, b.Hosts) {
		return fmt.Errorf("target host %q is not allowed by this token's binding (%s)", t.Host, b.String())
	}
	if len(b.PathPrefixes) > 0 {
		allowed := false
		for _, p := range b.PathPrefixes {
			if p != "" && strings.HasPrefix(t.Path, p) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("target path %q is not allowed by this token's binding (%s)", t.Path, b.String())
		}
	}
	for _, h := range b.Headers {
		needle := strings.ToLower(strings.TrimSpace(h)) + ":"
		if !strings.Contains(strings.ToLower(surface), needle) {
			return fmt.Errorf("the binding requires header %q to carry the value, but %q does not appear in the command", h, h)
		}
	}
	return nil
}

// CheckRedemption enforces the bindings recorded for the redeemed key names and
// returns the names that carried one. Unbound names are allowed: binding is
// opt-in at issue time, and the caller reports the unbound ones separately.
func CheckRedemption(sess *Session, names []string, t *Target, surface string) ([]string, error) {
	bound := make([]string, 0, len(names))
	for _, n := range SortedUnique(names) {
		b, ok := sess.Binding(n)
		if !ok || b.IsZero() {
			continue
		}
		if err := b.Check(t, surface); err != nil {
			return bound, fmt.Errorf("key %q: %w", n, err)
		}
		bound = append(bound, n)
	}
	return bound, nil
}

// UnboundNames returns the redeemed names that carry no binding, in sorted
// order, so the caller can warn about them.
func UnboundNames(sess *Session, names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range SortedUnique(names) {
		b, ok := sess.Binding(n)
		if !ok || b.IsZero() {
			out = append(out, n)
		}
	}
	return out
}
