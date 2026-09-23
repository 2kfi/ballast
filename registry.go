package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxManifestBytes = 10 << 20 // 10MB
	maxBlobBytes     = 2 << 30  // 2GB cap per blob fetch/push
	maxTagLen        = 128
)

type Server struct {
	cfg    *Config
	s      *Store
	m      *mirror
	log    *log.Logger
	q      sync.Mutex
	sess   map[string]string // upload session id -> temp file
	sessAt map[string]time.Time

	rlMu    sync.Mutex
	rlFail  map[string][]time.Time // ip -> recent failure times
	rlBlock map[string]time.Time   // ip -> blocked until

	auditMu sync.Mutex
	audit   *os.File
}

func NewServer(cfg *Config) (*Server, error) {
	s, err := openStore(cfg.Storage)
	if err != nil {
		return nil, err
	}
	// Sweep stale tmp files from crashes (bug: tmp leak).
	_ = filepath.Walk(filepath.Join(cfg.Storage, "tmp"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if time.Since(info.ModTime()) > time.Hour {
				os.Remove(p)
			}
		}
		return nil
	})
	srv := &Server{
		cfg: cfg, s: s,
		log:     log.New(os.Stdout, "goreg ", log.LstdFlags),
		sess:    map[string]string{},
		sessAt:  map[string]time.Time{},
		rlFail:  map[string][]time.Time{},
		rlBlock: map[string]time.Time{},
	}
	if cfg.AuditLog != "" {
		f, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
		srv.audit = f
	}
	srv.m = &mirror{cfg: cfg, s: s, u: newUpstream(cfg), log: srv.log}
	if len(cfg.Users) > 0 {
		srv.log.Printf("WARNING: %d plaintext user(s) in config; migrate to users_sha256 via `goreg hash`", len(cfg.Users))
	}
	return srv, nil
}

func (srv *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.route)
	return srv.auth(mux)
}

func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func (srv *Server) auditf(format string, a ...any) {
	if srv.audit == nil {
		return
	}
	srv.auditMu.Lock()
	defer srv.auditMu.Unlock()
	fmt.Fprintf(srv.audit, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, a...))
}

func (srv *Server) rlBlocked(ip string) bool {
	srv.rlMu.Lock()
	defer srv.rlMu.Unlock()
	if until, ok := srv.rlBlock[ip]; ok {
		if time.Now().Before(until) {
			return true
		}
		delete(srv.rlBlock, ip)
	}
	return false
}

func (srv *Server) rlNoteFail(ip string) {
	srv.rlMu.Lock()
	defer srv.rlMu.Unlock()
	now := time.Now()
	cut := now.Add(-time.Minute)
	kept := srv.rlFail[ip][:0]
	for _, t := range srv.rlFail[ip] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	srv.rlFail[ip] = kept
	if len(kept) >= 10 {
		srv.rlBlock[ip] = now.Add(5 * time.Minute)
		delete(srv.rlFail, ip)
	}
}

func (srv *Server) rlNoteOK(ip string) {
	srv.rlMu.Lock()
	defer srv.rlMu.Unlock()
	delete(srv.rlFail, ip)
}

// route dispatches the distribution-spec paths like python/manifests/3.12,
// myorg/app/blobs/uploads/<id>, ghcr.io/foo/bar/tags/list, ...
func (srv *Server) route(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ui" || r.URL.Path == "/ui/" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.uiIndex(w, r)
		return
	}
	if r.URL.Path == "/api/repos" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.apiRepos(w, r)
		return
	}
	if r.URL.Path == "/healthz" {
		srv.api(w)
		w.Write([]byte("ok"))
		return
	}
	srv.log.Printf("%s %s", r.Method, r.URL.Path)
	name, op, ref := parsePath(r.URL.Path)
	switch op {
	case "ping":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.ping(w, r)
	case "manifest":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			srv.manifestGet(w, r, name, ref)
		case http.MethodPut:
			srv.manifestPut(w, r, name, ref)
		case http.MethodDelete:
			srv.manifestDelete(w, r, name, ref)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "blob":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			srv.blobGet(w, r, name, ref)
		case http.MethodDelete:
			srv.blobDelete(w, r, name, ref)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "referrers":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.referrersGet(w, r, name, ref)
	case "tags":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.tagsGet(w, r, name)
	case "uploadStart":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		srv.uploadStart(w, r, name)
	case "upload":
		switch r.Method {
		case http.MethodPatch:
			srv.uploadChunk(w, r, ref)
		case http.MethodPut:
			srv.uploadPut(w, r, name, ref)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func parsePath(p string) (name, op, ref string) {
	rest := strings.TrimPrefix(p, "/v2/")
	rest = strings.Trim(rest, "/")
	switch {
	case rest == "":
		return "", "ping", ""
	case rest == "blobs/uploads" || strings.HasSuffix(rest, "/blobs/uploads"):
		return strings.TrimSuffix(rest, "/blobs/uploads"), "uploadStart", ""
	case strings.Contains(rest, "/blobs/uploads/"):
		i := strings.LastIndex(rest, "/blobs/uploads/")
		return rest[:i], "upload", rest[i+len("/blobs/uploads/"):]
	case strings.HasSuffix(rest, "/blobs/uploads"):
		// handled above; unreachable
		return "", "", ""
	case strings.Contains(rest, "/referrers/"):
		i := strings.LastIndex(rest, "/referrers/")
		return rest[:i], "referrers", rest[i+len("/referrers/"):]
	case strings.Contains(rest, "/blobs/"):
		i := strings.LastIndex(rest, "/blobs/")
		return rest[:i], "blob", rest[i+len("/blobs/"):]
	case strings.Contains(rest, "/manifests/"):
		i := strings.LastIndex(rest, "/manifests/")
		return rest[:i], "manifest", rest[i+len("/manifests/"):]
	case strings.HasSuffix(rest, "/tags/list"):
		return strings.TrimSuffix(rest, "/tags/list"), "tags", ""
	}
	return "", "", ""
}

func (srv *Server) api(w http.ResponseWriter) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
}

func (srv *Server) ping(w http.ResponseWriter, r *http.Request) {
	srv.api(w)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, "{}")
}

func (srv *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r) // unauthenticated: container probes, load balancers
			return
		}
		ip := clientIP(r)
		if srv.rlBlocked(ip) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		if srv.cfg.AllowAnonymous && r.URL.Path == "/v2/" {
			next.ServeHTTP(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		user, allowed := "", false
		if ok {
			allowed = srv.check(u, p)
			if allowed {
				user = u
			}
		}
		if !ok || !allowed {
			// Anonymous allowed only for safe reads when explicitly enabled.
			if srv.cfg.AllowAnonymous && (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
				(strings.HasPrefix(r.URL.Path, "/v2/") || r.URL.Path == "/ui" || r.URL.Path == "/api/repos" || r.URL.Path == "/healthz") {
				next.ServeHTTP(w, r)
				return
			}
			srv.rlNoteFail(ip)
			srv.auditf("auth-fail ip=%s path=%s", ip, r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Basic realm="goreg"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		srv.rlNoteOK(ip)
		r.Header.Set("X-Goreg-User", user)
		// Enforce pull-only roles on mutating methods.
		if r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch || r.Method == http.MethodPost {
			if srv.cfg.ReadOnly {
				http.Error(w, "read-only mode", http.StatusForbidden)
				return
			}
			if srv.cfg.roleOf(user) == "pull" {
				srv.auditf("forbidden user=%s method=%s path=%s", user, r.Method, r.URL.Path)
				http.Error(w, "forbidden: pull-only token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (srv *Server) check(user, pass string) bool {
	if user == "" || pass == "" {
		return false
	}
	if h, ok := srv.cfg.UsersSHA256[user]; ok {
		return verifySHA256(h, pass)
	}
	want, ok := srv.cfg.Users[user]
	if !ok {
		// Dummy compare to avoid user enumeration via timing.
		subtle.ConstantTimeCompare([]byte("dummy"), []byte(pass))
		return false
	}
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(pass)) == 1
}

// --- manifests ---

func (srv *Server) manifestGet(w http.ResponseWriter, r *http.Request, name, ref string) {
	srv.api(w)
	if strings.HasPrefix(ref, "sha256-") {
		ref = "sha256:" + strings.TrimPrefix(ref, "sha256-")
	}
	if !validName(name) {
		http.Error(w, "invalid repository name", http.StatusBadRequest)
		return
	}
	if isDigest(ref) {
		if !validDigest(ref) {
			http.Error(w, "bad digest", http.StatusBadRequest)
			return
		}
	} else if !validTag(ref) || len(ref) > maxTagLen {
		http.Error(w, "invalid tag", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(name, srv.cfg.Prefix+"/") {
		// frozen namespace: disk only, never upstream
		if isDigest(ref) {
			srv.serveLocalBlob(w, r, name, ref)
			return
		}
		e, ok := srv.s.GetTag(name, ref)
		if !ok {
			http.Error(w, "frozen tag not found (run goreg pull first)", http.StatusNotFound)
			return
		}
		srv.serveManifest(w, r, name, ref, e)
		return
	}

	if isDigest(ref) {
		// manifest-by-digest: serve cached, else lazily fetch from upstream
		if p, ok := srv.s.GetBlob(ref); ok {
			srv.serveFile(w, r, p, ref, "")
			return
		}
		if r.Method == http.MethodHead { // HEAD = existence probe, stay local
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		mr := srv.mirrorRef(name)
		if mr == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		b, d, uerr := srv.m.u.fetchManifest(*mr, ref)
		if uerr != nil {
			writeUpstreamError(w, uerr)
			return
		}
		if _, _, err := srv.s.PutBlob(bytes.NewReader(b), d); err != nil {
			http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
			return
		}
		srv.writeBlobBytes(w, r, b, d, sniffMediaType(b))
		return
	}

	e, err := srv.m.liveManifest(name, ref)
	if err != nil {
		if e == nil {
			if r.Method == http.MethodHead {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			writeUpstreamError(w, err)
			return
		}
	}
	if !srv.s.HasBlob(e.Digest) && e.UpstreamHost != "" {
		// tag survived but its blob was deleted: refetch by digest (cache miss)
		mr := manifestRef{host: e.UpstreamHost, path: e.UpstreamPath}
		if b, d, ferr := srv.m.u.fetchManifest(mr, e.Digest); ferr == nil {
			_, _, _ = srv.s.PutBlob(bytes.NewReader(b), d)
		}
	}
	srv.serveManifest(w, r, name, ref, e)
}

func writeUpstreamError(w http.ResponseWriter, err error) {
	msg := err.Error()
	if strings.Contains(msg, "404") || strings.Contains(msg, "Not Found") || strings.Contains(msg, "MANIFEST_UNKNOWN") {
		http.Error(w, "upstream: "+msg, http.StatusNotFound)
		return
	}
	http.Error(w, "upstream: "+msg, http.StatusBadGateway)
}

func (srv *Server) referrersGet(w http.ResponseWriter, r *http.Request, name, digest string) {
	srv.api(w)
	w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
	fmt.Fprintf(w, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
}

func (srv *Server) manifestPut(w http.ResponseWriter, r *http.Request, name, set string) {
	srv.api(w)
	if !validName(name) || !validTag(set) || len(set) > maxTagLen {
		http.Error(w, "invalid name/tag", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(name, srv.cfg.Prefix+"/") || srv.s.isMirrorRepo(name) {
		http.Error(w, "mirror/frozen repos are read-only", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxManifestBytes)
	b, err := io.ReadAll(io.LimitReader(r.Body, maxManifestBytes+1))
	if err != nil {
		http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
		return
	}
	if int64(len(b)) > maxManifestBytes {
		http.Error(w, "manifest too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !json.Valid(b) {
		http.Error(w, "manifest must be JSON", http.StatusBadRequest)
		return
	}
	var probe struct {
		SchemaVersion int             `json:"schemaVersion"`
		MediaType     string          `json:"mediaType"`
		Config        json.RawMessage `json:"config"`
		Layers        json.RawMessage `json:"layers"`
		Manifests     json.RawMessage `json:"manifests"`
	}
	if err := json.Unmarshal(b, &probe); err != nil || probe.SchemaVersion != 2 {
		http.Error(w, "manifest must be OCI/Docker schemaVersion 2", http.StatusBadRequest)
		return
	}
	d, _ := digestOfBytes(b)
	if _, _, err := srv.s.PutBlob(bytes.NewReader(b), d); err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	mt := r.Header.Get("Content-Type")
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = mt[:i]
	}
	if mt == "" || strings.Contains(mt, "octet-stream") {
		mt = sniffMediaType(b)
	}
	e := &tagEntry{Digest: d, MediaType: mt}
	if err := srv.s.SetTag(name, set, e); err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	srv.auditf("push user=%s %s:%s %s", r.Header.Get("X-Goreg-User"), name, set, d)
	w.Header().Set("Docker-Content-Digest", d)
	w.Header().Set("Location", "/v2/"+name+"/manifests/"+d)
	w.WriteHeader(http.StatusCreated)
}

func (srv *Server) serveManifest(w http.ResponseWriter, r *http.Request, name, ref string, e *tagEntry) {
	if p, ok := srv.s.GetBlob(e.Digest); ok {
		srv.serveFile(w, r, p, e.Digest, e.MediaType)
		return
	}
	http.Error(w, "digest missing from store", http.StatusInternalServerError)
}

// DELETE /v2/<name>/manifests/<tag|digest>: untag only, blobs stay (shared CAS, prune later).
func (srv *Server) manifestDelete(w http.ResponseWriter, r *http.Request, name, ref string) {
	srv.api(w)
	if !validName(name) {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	// Frozen/mirror repos are immutable via API.
	if strings.HasPrefix(name, srv.cfg.Prefix+"/") || srv.s.isMirrorRepo(name) {
		http.Error(w, "mirror/frozen repos are read-only", http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(ref, "sha256-") {
		ref = "sha256:" + strings.TrimPrefix(ref, "sha256-")
	}
	if isDigest(ref) {
		if !validDigest(ref) {
			http.Error(w, "bad digest", http.StatusBadRequest)
			return
		}
		var match []string
		for _, t := range srv.s.ListTags(name) {
			if e, _ := srv.s.GetTag(name, t); e != nil && e.Digest == ref {
				match = append(match, t)
			}
		}
		if len(match) == 0 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		for _, t := range match {
			_ = srv.s.DelTag(name, t)
		}
		srv.s.removeEmpty(name)
		srv.auditf("delete user=%s %s@%s (%d tags)", r.Header.Get("X-Goreg-User"), name, ref, len(match))
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if !validTag(ref) {
		http.Error(w, "invalid tag", http.StatusBadRequest)
		return
	}
	if _, ok := srv.s.GetTag(name, ref); !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	_ = srv.s.DelTag(name, ref)
	srv.s.removeEmpty(name)
	srv.auditf("delete user=%s %s:%s", r.Header.Get("X-Goreg-User"), name, ref)
	w.WriteHeader(http.StatusAccepted)
}

// DELETE /v2/<name>/blobs/<digest>: remove the CAS file. Callers must untag first;
// tags pointing at a deleted blob will 500 on serve until re-pulled (same as rm + prune).
func (srv *Server) blobDelete(w http.ResponseWriter, r *http.Request, name, digest string) {
	srv.api(w)
	if !validDigest(digest) {
		http.Error(w, "bad digest", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(name, srv.cfg.Prefix+"/") || srv.s.isMirrorRepo(name) {
		http.Error(w, "mirror/frozen repos are read-only", http.StatusMethodNotAllowed)
		return
	}
	// Refuse to delete blobs still referenced by any tag in this repo.
	for _, t := range srv.s.ListTags(name) {
		if e, _ := srv.s.GetTag(name, t); e != nil && e.Digest == digest {
			http.Error(w, "blob still referenced; untag first", http.StatusConflict)
			return
		}
	}
	if !srv.s.HasBlob(digest) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err := srv.s.DelBlob(digest); err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	srv.auditf("blob-delete user=%s %s@%s", r.Header.Get("X-Goreg-User"), name, digest)
	w.WriteHeader(http.StatusAccepted)
}

// mirrorRef returns upstream location for name, or nil if it's a client-owned repo.
func (srv *Server) mirrorRef(name string) *manifestRef {
	tags := srv.s.ListTags(name)
	if len(tags) > 0 {
		mirror := false
		for _, t := range tags {
			if e, _ := srv.s.GetTag(name, t); e.UpstreamHost != "" {
				mirror = true
				break
			}
		}
		if !mirror {
			return nil // client-owned repo: nothing goes upstream
		}
	}
	mr := resolveName(name)
	return &mr
}

// --- blobs ---

func (srv *Server) blobGet(w http.ResponseWriter, r *http.Request, name, digest string) {
	srv.api(w)
	if !validDigest(digest) {
		http.Error(w, "bad digest", http.StatusBadRequest)
		return
	}
	if !validName(name) {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	frozen := strings.HasPrefix(name, srv.cfg.Prefix+"/")
	if p, ok := srv.s.GetBlob(digest); ok {
		srv.serveFile(w, r, p, digest, "")
		return
	}
	if frozen || r.Method == http.MethodHead {
		if frozen {
			http.Error(w, "blob not cached (frozen repo is offline)", http.StatusNotFound)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
		return
	}
	mr := srv.mirrorRef(name)
	if mr == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// lazy pass-through fetch
	f, err := os.CreateTemp(filepath.Join(srv.cfg.Storage, "tmp"), "blob")
	if err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpName := f.Name()
	n, err := srv.m.u.fetchBlob(*mr, digest, f)
	_ = f.Sync()
	_ = f.Close()
	if err != nil {
		os.Remove(tmpName)
		writeUpstreamError(w, err)
		return
	}
	if err := srv.s.PutBlobFromFile(tmpName, digest); err != nil {
		os.Remove(tmpName)
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	os.Remove(tmpName)
	p, _ := srv.s.GetBlob(digest)
	srv.serveFile(w, r, p, digest, "")
	_ = n
}

func (srv *Server) serveLocalBlob(w http.ResponseWriter, r *http.Request, _, digest string) {
	srv.api(w)
	if p, ok := srv.s.GetBlob(digest); ok {
		srv.serveFile(w, r, p, digest, "")
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (srv *Server) serveFile(w http.ResponseWriter, r *http.Request, path, digest, mt string) {
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "store read: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if _, err := f.Stat(); err != nil {
		http.Error(w, "store stat: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	if mt != "" {
		w.Header().Set("Content-Type", mt)
	}
	http.ServeContent(w, r, "", time.Unix(0, 0), f)
}

func (srv *Server) writeBlobBytes(w http.ResponseWriter, r *http.Request, b []byte, digest, mt string) {
	w.Header().Set("Docker-Content-Digest", digest)
	if mt != "" {
		w.Header().Set("Content-Type", mt)
	}
	if b == nil {
		return // caller will ServeContent after
	}
	w.WriteHeader(http.StatusOK)
	w.Write(b)
	_ = r
}

// --- tags ---

func (srv *Server) tagsGet(w http.ResponseWriter, r *http.Request, name string) {
	srv.api(w)
	tags := srv.s.ListTags(name)
	if tags == nil {
		tags = []string{}
	}
	out, _ := json.Marshal(struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}{name, tags})
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// --- uploads (client push) ---

func (srv *Server) uploadStart(w http.ResponseWriter, r *http.Request, name string) {
	srv.api(w)
	if !validName(name) {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	if m := r.URL.Query().Get("mount"); m != "" {
		d := canonDigest(m)
		if d == "" || !validDigest(d) {
			http.Error(w, "bad mount digest", http.StatusBadRequest)
			return
		}
		if srv.s.HasBlob(d) {
			w.Header().Set("Docker-Content-Digest", d)
			w.Header().Set("Location", "/v2/"+name+"/blobs/"+d)
			w.WriteHeader(http.StatusCreated)
			return
		}
	}
	id, err := newID()
	if err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	f, err := os.CreateTemp(filepath.Join(srv.cfg.Storage, "tmp"), "up-"+id)
	if err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	f.Close()
	srv.q.Lock()
	srv.sess[id] = f.Name()
	srv.sessAt[id] = time.Now()
	// Opportunistic expiry of sessions older than 1h.
	for sid, at := range srv.sessAt {
		if time.Since(at) > time.Hour {
			if p, ok := srv.sess[sid]; ok {
				os.Remove(p)
			}
			delete(srv.sess, sid)
			delete(srv.sessAt, sid)
		}
	}
	srv.q.Unlock()
	w.Header().Set("Location", "/v2/"+name+"/blobs/uploads/"+id)
	w.Header().Set("Docker-Upload-UUID", id)
	w.WriteHeader(http.StatusAccepted)
}

func (srv *Server) uploadChunk(w http.ResponseWriter, r *http.Request, id string) {
	srv.api(w)
	srv.q.Lock()
	p := srv.sess[id]
	srv.q.Unlock()
	if p == "" {
		http.Error(w, "no such upload", http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBlobBytes)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if st, err := f.Stat(); err == nil && st.Size() > maxBlobBytes {
		f.Close()
		http.Error(w, "blob too large", http.StatusRequestEntityTooLarge)
		return
	}
	if _, err := io.Copy(f, io.LimitReader(r.Body, maxBlobBytes+1)); err != nil {
		f.Close()
		http.Error(w, "write: "+err.Error(), http.StatusBadRequest)
		return
	}
	f.Close()
	st, err := os.Stat(p)
	if err != nil {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if st.Size() == 0 {
		w.Header().Set("Range", "0-0")
	} else {
		w.Header().Set("Range", "0-"+strconv.FormatInt(st.Size()-1, 10))
	}
	w.Header().Set("Docker-Upload-UUID", id)
	w.WriteHeader(http.StatusAccepted)
}

func (srv *Server) uploadPut(w http.ResponseWriter, r *http.Request, name, id string) {
	srv.api(w)
	if !validName(name) {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	srv.q.Lock()
	p := srv.sess[id]
	delete(srv.sess, id)
	delete(srv.sessAt, id)
	srv.q.Unlock()
	if p == "" {
		http.Error(w, "no such upload", http.StatusNotFound)
		return
	}
	defer os.Remove(p)
	r.Body = http.MaxBytesReader(w, r.Body, maxBlobBytes)
	if f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		if _, err := io.Copy(f, io.LimitReader(r.Body, maxBlobBytes+1)); err != nil {
			f.Close()
			http.Error(w, "write: "+err.Error(), http.StatusBadRequest)
			return
		}
		f.Close()
	} else {
		http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if st, err := os.Stat(p); err == nil && st.Size() > maxBlobBytes {
		http.Error(w, "blob too large", http.StatusRequestEntityTooLarge)
		return
	}
	want := canonDigest(r.URL.Query().Get("digest"))
	if want == "" || !validDigest(want) {
		http.Error(w, "valid digest required", http.StatusBadRequest)
		return
	}
	if err := srv.s.PutBlobFromFile(p, want); err != nil {
		http.Error(w, "digest mismatch: "+err.Error(), http.StatusBadRequest)
		return
	}
	srv.auditf("blob-push user=%s %s@%s", r.Header.Get("X-Goreg-User"), name, want)
	w.Header().Set("Docker-Content-Digest", want)
	w.Header().Set("Location", "/v2/"+name+"/blobs/"+want)
	w.WriteHeader(http.StatusCreated)
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func canonDigest(d string) string {
	if isDigest(d) && len(d) == 71 && validDigest(d) { // "sha256:" + 64 hex
		return d
	}
	return ""
}
