package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const manifestAccept = "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v1+json"

// manifestRef is the canonical upstream location of a repo+tag.
type manifestRef struct {
	host string // registry host, e.g. docker.io, ghcr.io, 127.0.0.1:5000
	path string // canonical repo path, e.g. library/python
}

// resolveName maps a user-facing repository path to its upstream location.
// "python" -> docker.io/library/python; "valkey/valkey" -> docker.io/valkey/valkey;
// "ghcr.io/foo/bar" -> ghcr.io/foo/bar.
func resolveName(name string) manifestRef {
	if i := strings.IndexAny(name, ".:"); i >= 0 && !strings.Contains(name[:i], "/") {
		// foreign host in first path component (ghcr.io/..., host:port/...)
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 1 {
			return manifestRef{host: parts[0], path: parts[0]}
		}
		return manifestRef{host: parts[0], path: parts[1]}
	}
	// docker.io default; apply library/ shorthand for single-component names
	switch strings.SplitN(name, "/", 2)[0] {
	case "docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		rest := strings.SplitN(name, "/", 2)[1]
		if !strings.Contains(rest, "/") {
			return manifestRef{host: "docker.io", path: "library/" + rest}
		}
		return manifestRef{host: "docker.io", path: rest}
	}
	if strings.Contains(name, "/") {
		return manifestRef{host: "docker.io", path: name}
	}
	return manifestRef{host: "docker.io", path: "library/" + name}
}

type upstreamClient struct {
	cfg    *Config
	http   *http.Client
	mu     sync.Mutex
	tokens map[string]token  // keyed host+scope+user
	auth   map[string]string // host -> basic user:pass or bearer hint
	fail   map[string]time.Time
}

type token struct {
	value string
	until time.Time
}

func newUpstream(cfg *Config) *upstreamClient {
	return &upstreamClient{
		cfg: cfg,
		http: &http.Client{
			Timeout: 5 * time.Minute,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				// Don't leak Authorization across hosts.
				if len(via) > 0 && req.URL.Host != via[0].URL.Host {
					req.Header.Del("Authorization")
				}
				return nil
			},
		},
		tokens: map[string]token{},
		auth:   map[string]string{},
		fail:   map[string]time.Time{},
	}
}

// do performs an authed GET/HEAD to upstream host, handling both Basic and
// Bearer WWW-Authenticate challenges (docker.io, ghcr.io, quay.io, ...).
func (u *upstreamClient) do(method, host, upath string, accept string) (*http.Response, error) {
	base := u.cfg.upstreamBase(host)
	u.mu.Lock()
	user, pass := "", ""
	if c, ok := u.cfg.Upstreams[host]; ok {
		user, pass = c.Username, c.Password
	}
	u.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		full, err := url.JoinPath(base, "/v2/"+strings.TrimPrefix(upath, "/"))
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(method, full, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if user != "" || pass != "" {
			req.SetBasicAuth(user, pass)
		} else if t := u.bearer(host, upath, user); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
		resp, err := u.http.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusUnauthorized {
			return resp, nil
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		if challenge == "" {
			return nil, fmt.Errorf("upstream %s: unauthorized (no challenge)", host)
		}
		if err := u.obtainToken(host, upath, user, pass, challenge); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("upstream %s: authorization failed after retry", host)
}

func scopeOf(upath string) string {
	// Token scope is the repo, not the full path+ref: "library/python/manifests/latest" -> "library/python".
	if i := strings.Index(upath, "/manifests/"); i >= 0 {
		return upath[:i]
	}
	if i := strings.Index(upath, "/blobs/"); i >= 0 {
		return upath[:i]
	}
	return upath
}

func (u *upstreamClient) bearer(host, upath, user string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	// Sweep expired tokens opportunistically.
	for k, t := range u.tokens {
		if time.Now().After(t.until) {
			delete(u.tokens, k)
		}
	}
	if t, ok := u.tokens[host+"/"+user+"/"+scopeOf(upath)]; ok && time.Now().Before(t.until) {
		return t.value
	}
	return ""
}

func (u *upstreamClient) obtainToken(host, upath, user, pass, challenge string) error {
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer ") {
		return fmt.Errorf("upstream %s: unsupported auth challenge %q", host, challenge)
	}
	params := parseChallenge(challenge[len("Bearer "):])
	realm := params["realm"]
	if realm == "" {
		return fmt.Errorf("upstream %s: bearer realm missing", host)
	}
	ru, err := url.Parse(realm)
	if err != nil || (ru.Scheme != "https" && ru.Scheme != "http") || ru.Host == "" {
		return fmt.Errorf("upstream %s: bad token realm %q", host, realm)
	}
	// Only allow https realms, except loopback for local testing.
	if ru.Scheme != "https" && !isLoopbackHost(ru.Hostname()) {
		return fmt.Errorf("upstream %s: token realm must be https: %q", host, realm)
	}
	q := ru.Query()
	if v := params["service"]; v != "" {
		q.Set("service", v)
	}
	if v := params["scope"]; v != "" {
		q.Set("scope", v)
	}
	ru.RawQuery = q.Encode()
	req, err := http.NewRequest("GET", ru.String(), nil)
	if err != nil {
		return err
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := u.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token endpoint %s: status %d", realm, resp.StatusCode)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t); err != nil {
		return err
	}
	val := t.Token
	if val == "" {
		val = t.AccessToken
	}
	if val == "" {
		return fmt.Errorf("token endpoint %s: no token", realm)
	}
	ttl := time.Duration(t.ExpiresIn) * time.Second
	if ttl < time.Minute {
		ttl = 60 * time.Second
	}
	u.mu.Lock()
	u.tokens[host+"/"+user+"/"+scopeOf(upath)] = token{value: val, until: time.Now().Add(ttl)}
	u.mu.Unlock()
	return nil
}

// parseChallenge parses RFC7235 auth-params, respecting quoted commas.
func parseChallenge(s string) map[string]string {
	out := map[string]string{}
	var key, val strings.Builder
	inQuotes := false
	phase := 0 // 0=key, 1=val
	flush := func() {
		k := strings.ToLower(strings.TrimSpace(key.String()))
		v := strings.Trim(strings.TrimSpace(val.String()), `"`)
		if k != "" {
			out[k] = v
		}
		key.Reset()
		val.Reset()
		phase = 0
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			val.WriteRune(r)
		case r == '=' && !inQuotes && phase == 0:
			phase = 1
		case r == ',' && !inQuotes:
			flush()
		default:
			if phase == 0 {
				key.WriteRune(r)
			} else {
				val.WriteRune(r)
			}
		}
	}
	flush()
	return out
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "127.")
}

// fetchManifest returns the manifest bytes + docker-content-digest (computed if absent).
func (u *upstreamClient) fetchManifest(ref manifestRef, tag string) ([]byte, string, error) {
	if !validTag(tag) && !validDigest(tag) {
		return nil, "", fmt.Errorf("invalid tag/digest %q", tag)
	}
	resp, err := u.do("GET", ref.host, ref.path+"/manifests/"+url.PathEscape(tag), manifestAccept)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("upstream %s: GET manifest %s: %s", ref.host, tag, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(b)) > maxManifestBytes {
		return nil, "", fmt.Errorf("upstream manifest too large")
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if d == "" || !validDigest(d) {
		// manifests are stored uncompressed upstream; digest of the body is canonical
		d, _ = digestOfBytes(b)
	}
	return b, d, nil
}

func (u *upstreamClient) fetchBlob(ref manifestRef, digest string, w io.Writer) (int64, error) {
	if !validDigest(digest) {
		return 0, fmt.Errorf("invalid digest %q", digest)
	}
	resp, err := u.do("GET", ref.host, ref.path+"/blobs/"+digest, "")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("upstream %s: GET blob %s: %s", ref.host, digest, resp.Status)
	}
	return io.Copy(w, io.LimitReader(resp.Body, maxBlobBytes))
}

func (u *upstreamClient) listTags(ref manifestRef) ([]string, error) {
	resp, err := u.do("GET", ref.host, ref.path+"/tags/list", "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream %s: tags/list: %s", ref.host, resp.Status)
	}
	var out struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Tags, nil
}
