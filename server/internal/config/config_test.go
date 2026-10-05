package config

import (
	"strings"
	"testing"
)

func TestTURNSecretMustSurviveCoturnsConfigParser(t *testing.T) {
	ok := []string{
		"B6w6pXn2Qy+Yb1/Lr8sZk3TfVu9aWc0dEe4gHh5iJj6kKm7lLn8oOp9qQr0sSt1u", // openssl rand -base64 48
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", // openssl rand -hex 32
		"Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG8=",             // padded base64
		"url-safe_secret.with-dots_and-dashes.0123456789",
	}
	bad := []string{
		"=K7f9" + strings.Repeat("a", 40),                // coturn skips the leading '='
		`"K7f9` + strings.Repeat("a", 40),                // and a leading quote
		strings.Repeat("a", 40) + ";",                    // a trailing ';' is warned about, secret and all
		strings.Repeat("a", 20) + " " + "b1234567890123", // blanks
		strings.Repeat("a", 40) + "\r",                   // a CRLF .env
	}
	for _, s := range ok {
		t.Setenv("DOOMMSG_TURN_SECRET", s)
		if _, err := Load(); err != nil {
			t.Errorf("%q rejected: %v", s, err)
		}
	}
	for _, s := range bad {
		t.Setenv("DOOMMSG_TURN_SECRET", s)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "may only contain") {
			t.Errorf("%q accepted (err %v)", s, err)
		}
	}
}
