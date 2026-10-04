// Package validate holds input validation shared by the API and the hub.
package validate

import (
	"encoding/base64"
	"errors"
	"regexp"
)

var usernameRe = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

// Username reports whether u is a valid, canonical username.
func Username(u string) bool { return usernameRe.MatchString(u) }

// Key32 decodes a base64url (unpadded) 32-byte public key.
func Key32(s string) ([]byte, error) { return fixed(s, 32) }

// Sig64 decodes a base64url (unpadded) 64-byte Ed25519 signature.
func Sig64(s string) ([]byte, error) { return fixed(s, 64) }

func fixed(s string, n int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid base64url")
	}
	if len(b) != n {
		return nil, errors.New("invalid length")
	}
	return b, nil
}

// B64 encodes bytes as unpadded base64url, the wire format for all binary
// fields.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
