// Package turn issues short-lived TURN credentials compatible with coturn's
// "use-auth-secret" (TURN REST API) mode, so no long-lived TURN password
// ever reaches a client.
package turn

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // mandated by the TURN REST API / coturn
	"encoding/base64"
	"strconv"
	"time"
)

type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

type Credentials struct {
	ICEServers []ICEServer `json:"iceServers"`
	ExpiresAt  int64       `json:"expiresAt"`
}

type Issuer struct {
	Secret []byte
	URLs   []string
	STUN   []string
	TTL    time.Duration
}

// Issue returns credentials for user, valid for the configured TTL.
func (i *Issuer) Issue(user string, now time.Time) Credentials {
	exp := now.Add(i.TTL).Unix()
	var out Credentials
	out.ExpiresAt = exp
	if len(i.STUN) > 0 {
		out.ICEServers = append(out.ICEServers, ICEServer{URLs: i.STUN})
	}
	if len(i.URLs) > 0 && len(i.Secret) > 0 {
		username := strconv.FormatInt(exp, 10) + ":" + user
		mac := hmac.New(sha1.New, i.Secret)
		mac.Write([]byte(username))
		out.ICEServers = append(out.ICEServers, ICEServer{
			URLs:       i.URLs,
			Username:   username,
			Credential: base64.StdEncoding.EncodeToString(mac.Sum(nil)),
		})
	}
	if out.ICEServers == nil {
		out.ICEServers = []ICEServer{}
	}
	return out
}
