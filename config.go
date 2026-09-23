package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

var validPrefixRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)

// hashToken formats a salted sha256 verifier for config: "salt:hex(sha256(salt:token))".
func hashToken(token, salt string) string {
	h := sha256.Sum256([]byte(salt + ":" + token))
	return salt + ":" + hex.EncodeToString(h[:])
}

// newSalt returns 16 random hex chars; falls back to timestamp on CSPRNG failure.
func newSalt() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func verifySHA256(stored, token string) bool {
	salt, want, ok := strings.Cut(stored, ":")
	if !ok || salt == "" || want == "" {
		return false
	}
	h := sha256.Sum256([]byte(salt + ":" + token))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h[:])), []byte(want)) == 1
}

type UpstreamCred struct {
	URL      string `json:"url,omitempty"` // override base, e.g. https://registry-1.docker.io
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Config struct {
	Addr           string                  `json:"addr"`                     // listen address, e.g. ":5000"
	Storage        string                  `json:"storage"`                  // data dir
	Prefix         string                  `json:"prefix"`                   // frozen namespace prefix, default "goreg"
	Users          map[string]string       `json:"users"`                    // basic-auth user -> plaintext token (legacy; prefer users_sha256)
	UsersSHA256    map[string]string       `json:"users_sha256,omitempty"`   // user -> "salt:hex(sha256(salt:token))" (use `goreg hash`)
	Roles          map[string]string       `json:"roles,omitempty"`          // user -> "pull"|"push"|"admin" (default "admin")
	AllowAnonymous bool                    `json:"allowAnonymous,omitempty"` // must be explicit; default false (fail closed)
	BehindProxy    bool                    `json:"behindProxy,omitempty"`    // set true when TLS terminates at reverse proxy
	ReadOnly       bool                    `json:"readOnly,omitempty"`       // refuse all PUT/DELETE/PATCH/POST uploads
	AuditLog       string                  `json:"auditLog,omitempty"`       // path, default "<storage>/audit.log" ("" disables)
	Upstreams      map[string]UpstreamCred `json:"upstreams"`                // per-host creds/base override
	TTL            struct {
		Version  string `json:"version"`  // version-looking tags, default 24h
		Floating string `json:"floating"` // latest etc, default 15m
	} `json:"ttl"`
	DefaultPlatform string `json:"defaultPlatform,omitempty"` // "linux/amd64"
}

func loadConfig(path string) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Addr == "" {
		c.Addr = ":5000"
	}
	if c.Storage == "" {
		c.Storage = "data"
	}
	if c.Prefix == "" {
		c.Prefix = "goreg"
	}
	if !validPrefixRe.MatchString(c.Prefix) {
		return nil, fmt.Errorf("invalid prefix %q: must match %s", c.Prefix, validPrefixRe.String())
	}
	if c.DefaultPlatform == "" {
		c.DefaultPlatform = "linux/amd64"
	}
	if c.TTL.Version == "" {
		c.TTL.Version = "24h"
	}
	if c.TTL.Floating == "" {
		c.TTL.Floating = "15m"
	}
	if _, err := time.ParseDuration(c.TTL.Version); err != nil {
		return nil, fmt.Errorf("invalid ttl.version %q: %w", c.TTL.Version, err)
	}
	if _, err := time.ParseDuration(c.TTL.Floating); err != nil {
		return nil, fmt.Errorf("invalid ttl.floating %q: %w", c.TTL.Floating, err)
	}
	if c.AuditLog == "" {
		c.AuditLog = ""
	}
	// Fail closed: no users configured and no explicit opt-in => refuse to start.
	if len(c.Users) == 0 && len(c.UsersSHA256) == 0 && !c.AllowAnonymous {
		return nil, fmt.Errorf("no users configured and allowAnonymous is not true: refusing to start open (set users/users_sha256 or allowAnonymous)")
	}
	for u, h := range c.UsersSHA256 {
		if _, _, ok := strings.Cut(h, ":"); !ok {
			return nil, fmt.Errorf("invalid users_sha256 entry for %q: want \"salt:hex\"", u)
		}
	}
	for u, r := range c.Roles {
		if r != "pull" && r != "push" && r != "admin" {
			return nil, fmt.Errorf("invalid role %q for user %q: want pull|push|admin", r, u)
		}
	}
	return c, nil
}

func (c *Config) roleOf(user string) string {
	if r, ok := c.Roles[user]; ok {
		return r
	}
	return "admin" // backward compat: unlisted users keep full access
}

func (c *Config) duration(field string) time.Duration {
	v := c.TTL.Version
	if field == "floating" {
		v = c.TTL.Floating
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if field == "floating" {
		return 15 * time.Minute
	}
	return 24 * time.Hour
}

func (c *Config) upstreamBase(host string) string {
	if u, ok := c.Upstreams[host]; ok && u.URL != "" {
		return u.URL
	}
	if host == "docker.io" {
		return "https://registry-1.docker.io"
	}
	return "https://" + host
}
