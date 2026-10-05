// Package config loads server configuration from the environment.
//
// Every option is an environment variable prefixed with DOOMMSG_ so the
// server is trivially configurable from containers, systemd units and
// Kubernetes manifests without config files.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Listen is the address of the public HTTP/WebSocket listener.
	Listen string
	// MetricsListen is the address of the Prometheus/health listener.
	// Keep it off the public interface. Empty disables it.
	MetricsListen string
	// DBPath is the SQLite database file.
	DBPath string

	// AllowedOrigins restricts which browser origins may open WebSockets
	// and call the API. Empty means same-origin only.
	AllowedOrigins []string
	// TrustProxy makes the server honour X-Forwarded-For from the reverse
	// proxy for rate limiting. Only enable it behind a trusted proxy.
	TrustProxy bool

	// RegistrationCode, when set, is required to create an account. This
	// keeps a private deployment private.
	RegistrationCode string

	// TURN settings (coturn "use-auth-secret" REST API credentials).
	TURNSecret string
	TURNURLs   []string
	TURNTTL    time.Duration
	// STUNURLs are offered in addition to TURN.
	STUNURLs []string

	// SessionTTL is how long an auth token stays valid.
	SessionTTL time.Duration
	// MailboxTTL is how long an undelivered envelope is kept.
	MailboxTTL time.Duration
	// MailboxMax caps queued envelopes per recipient.
	MailboxMax int
	// MailboxMaxBytes caps the queued payload bytes per recipient.
	MailboxMaxBytes int

	LogLevel string
}

func Load() (*Config, error) {
	c := &Config{
		Listen:           env("DOOMMSG_LISTEN", ":8080"),
		MetricsListen:    env("DOOMMSG_METRICS_LISTEN", "127.0.0.1:9090"),
		DBPath:           env("DOOMMSG_DB", "doommsg.db"),
		AllowedOrigins:   list(os.Getenv("DOOMMSG_ALLOWED_ORIGINS")),
		RegistrationCode: os.Getenv("DOOMMSG_REGISTRATION_CODE"),
		TURNSecret:       os.Getenv("DOOMMSG_TURN_SECRET"),
		TURNURLs:         list(os.Getenv("DOOMMSG_TURN_URLS")),
		STUNURLs:         list(os.Getenv("DOOMMSG_STUN_URLS")),
		LogLevel:         env("DOOMMSG_LOG_LEVEL", "info"),
	}

	var err error
	if c.TrustProxy, err = boolEnv("DOOMMSG_TRUST_PROXY", false); err != nil {
		return nil, err
	}
	if c.TURNTTL, err = durationEnv("DOOMMSG_TURN_TTL", 12*time.Hour); err != nil {
		return nil, err
	}
	if c.SessionTTL, err = durationEnv("DOOMMSG_SESSION_TTL", 30*24*time.Hour); err != nil {
		return nil, err
	}
	if c.MailboxTTL, err = durationEnv("DOOMMSG_MAILBOX_TTL", 30*24*time.Hour); err != nil {
		return nil, err
	}
	if c.MailboxMax, err = intEnv("DOOMMSG_MAILBOX_MAX", 10000); err != nil {
		return nil, err
	}
	if c.MailboxMaxBytes, err = intEnv("DOOMMSG_MAILBOX_MAX_BYTES", 64<<20); err != nil {
		return nil, err
	}

	if len(c.TURNURLs) > 0 && c.TURNSecret == "" {
		return nil, errors.New("DOOMMSG_TURN_URLS is set but DOOMMSG_TURN_SECRET is empty")
	}
	if c.TURNSecret != "" && len(c.TURNSecret) < 32 {
		return nil, errors.New("DOOMMSG_TURN_SECRET must be at least 32 characters")
	}
	if c.TURNSecret != "" && !TURNSecretOK(c.TURNSecret) {
		return nil, errors.New("DOOMMSG_TURN_SECRET may only contain letters, digits and + / = _ . - and must not start with = " +
			"(generate one with: openssl rand -base64 48)")
	}
	if c.MailboxMax < 1 {
		return nil, errors.New("DOOMMSG_MAILBOX_MAX must be positive")
	}
	// One sender may fill a tenth of a mailbox; that tenth must still hold
	// the largest envelope (96 KiB).
	if c.MailboxMaxBytes < 1<<20 {
		return nil, errors.New("DOOMMSG_MAILBOX_MAX_BYTES must be at least 1048576 (1 MiB)")
	}
	return c, nil
}

// TURNSecretOK reports whether coturn reads s back from a config file
// exactly as written. Its parser drops a leading '=', '"' or blank and
// warns about (and logs) a trailing ';', so with such a secret the relay
// and coturn would sign credentials with different keys. The coturn
// entrypoint in deploy/docker-compose.yml applies the same rule.
func TURNSecretOK(s string) bool {
	if strings.HasPrefix(s, "=") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("+/=_.-", r)) {
			return false
		}
	}
	return true
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func list(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolEnv(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

func intEnv(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return i, nil
}

func durationEnv(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", key)
	}
	return d, nil
}
