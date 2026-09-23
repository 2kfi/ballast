package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

var (
	validDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	validNameRe   = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	validTagRe    = regexp.MustCompile(`^[\w][\w.-]{0,127}$`)
)

func validDigest(d string) bool { return validDigestRe.MatchString(d) }
func validName(n string) bool {
	if n == "" || len(n) > 255 || strings.Contains(n, "..") || strings.Contains(n, "//") {
		return false
	}
	return validNameRe.MatchString(n)
}
func validTag(t string) bool { return validTagRe.MatchString(t) }

// tagEntry is one tag pointer. Mirror tags (pulled through) carry the
// upstream/live metadata; client-pushed tags carry none of it.
type tagEntry struct {
	Digest       string `json:"digest"`
	MediaType    string `json:"mediaType"`
	UpstreamHost string `json:"upstreamHost,omitempty"`
	UpstreamPath string `json:"upstreamPath,omitempty"`
	Floating     bool   `json:"floating,omitempty"`
	LastChecked  int64  `json:"lastChecked,omitempty"` // unix seconds
	Frozen       string `json:"frozen,omitempty"`      // concrete tag created under prefix repo
}

type repoState struct {
	Tags map[string]*tagEntry
}

type Store struct {
	root string
	mu   sync.Mutex // ponytail: global lock, revalidation fetches happen outside it
	load map[string]*repoState
}

func openStore(root string) (*Store, error) {
	s := &Store{root: root, load: map[string]*repoState{}}
	for _, d := range []string{"blobs/sha256", "repo", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) blobPath(digest string) string {
	// Caller must validate with validDigest first; TrimPrefix keeps path tight.
	return filepath.Join(s.root, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))
}

func (s *Store) HasBlob(digest string) bool {
	if !validDigest(digest) {
		return false
	}
	_, err := os.Stat(s.blobPath(digest))
	return err == nil
}

func (s *Store) GetBlob(digest string) (string, bool) {
	if !validDigest(digest) {
		return "", false
	}
	p := s.blobPath(digest)
	if !s.HasBlob(digest) {
		return "", false
	}
	return p, true
}

// PutBlob streams r into the CAS, verifying it hashes to digest ("" = accept any, compute).
func (s *Store) PutBlob(r io.Reader, want string) (string, int64, error) {
	if want != "" && !validDigest(want) {
		return "", 0, fmt.Errorf("invalid digest %q", want)
	}
	tmp, err := os.CreateTemp(filepath.Join(s.root, "tmp"), "blob")
	if err != nil {
		return "", 0, err
	}
	tmpName := tmp.Name()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", 0, err
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if want != "" && want != got {
		tmp.Close()
		os.Remove(tmpName)
		return "", 0, fmt.Errorf("digest mismatch: want %s got %s", want, got)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", 0, err
	}
	final := s.blobPath(got)
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		os.Remove(tmpName)
		return "", 0, err
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		if !s.HasBlob(got) {
			return "", 0, err
		}
	}
	return got, n, nil
}

func (s *Store) repoDir(name string) string { return filepath.Join(s.root, "repo", name) }

func (s *Store) repoPath(name string) string { return filepath.Join(s.repoDir(name), "tags.json") }

func (s *Store) repo(name string) *repoState {
	if r, ok := s.load[name]; ok {
		return r
	}
	r := &repoState{Tags: map[string]*tagEntry{}}
	if b, err := os.ReadFile(s.repoPath(name)); err == nil {
		if err := json.Unmarshal(b, r); err != nil {
			// Corrupt file: keep backup, start empty but do NOT overwrite yet.
			_ = os.WriteFile(s.repoPath(name)+".corrupt", b, 0o644)
		}
	}
	if r.Tags == nil {
		r.Tags = map[string]*tagEntry{}
	}
	s.load[name] = r
	return r
}

func (s *Store) persist(name string) error {
	st := s.repo(name)
	b, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	dir := s.repoDir(name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(s.root, "tmp", "tags-"+sanitize(name)+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.repoPath(name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func sanitize(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

// PutBlobFromFile moves an already-fetched temp file into the CAS, verifying digest.
func (s *Store) PutBlobFromFile(path, want string) error {
	if !validDigest(want) {
		return fmt.Errorf("invalid digest %q", want)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, _, err = s.PutBlob(f, want)
	return err
}

func copyEntry(e *tagEntry) *tagEntry {
	if e == nil {
		return nil
	}
	c := *e
	return &c
}

func (s *Store) GetTag(name, tag string) (*tagEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validName(name) || !validTag(tag) {
		return nil, false
	}
	e, ok := s.repo(name).Tags[tag]
	return copyEntry(e), ok
}

func (s *Store) SetTag(name, tag string, e *tagEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validName(name) || !validTag(tag) {
		return fmt.Errorf("invalid name/tag")
	}
	s.repo(name).Tags[tag] = copyEntry(e)
	return s.persist(name)
}

// SetFrozen writes a tag in the frozen (prefix) repo pointing at digest; it's read-only content.
func (s *Store) SetFrozen(frozenRepo, frozenTag string, digest, mediaType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if digest == "" || !validDigest(digest) {
		return fmt.Errorf("cannot freeze empty/invalid digest")
	}
	if !validName(frozenRepo) || !validTag(frozenTag) {
		return fmt.Errorf("invalid frozen repo/tag")
	}
	s.repo(frozenRepo).Tags[frozenTag] = &tagEntry{Digest: digest, MediaType: mediaType}
	return s.persist(frozenRepo)
}

func (s *Store) ListTags(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validName(name) {
		return nil
	}
	tags := make([]string, 0, len(s.repo(name).Tags))
	for t := range s.repo(name).Tags {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

func (s *Store) DelTag(name, tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validName(name) || !validTag(tag) {
		return fmt.Errorf("invalid name/tag")
	}
	delete(s.repo(name).Tags, tag)
	return s.persist(name)
}

func (s *Store) isMirrorRepo(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.repo(name).Tags {
		if e.UpstreamHost != "" {
			return true
		}
	}
	return false
}

func (s *Store) DelBlob(digest string) error {
	if !validDigest(digest) {
		return fmt.Errorf("bad digest")
	}
	return os.Remove(s.blobPath(digest))
}

// ListRepos scans storage for repos (used by UI/API). Cheap: reads repo dir names.
func (s *Store) ListRepos() []string {
	root := filepath.Join(s.root, "repo")
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && d.Name() == "tags.json" {
			rel, err := filepath.Rel(root, filepath.Dir(p))
			if err == nil && validName(filepath.ToSlash(rel)) {
				out = append(out, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// DiskUsage returns blob bytes + counts for UI/health.
func (s *Store) DiskUsage() (blobs int, bytes int64) {
	root := filepath.Join(s.root, "blobs", "sha256")
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			blobs++
			bytes += info.Size()
		}
		return nil
	})
	return blobs, bytes
}

func (s *Store) removeEmpty(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.repo(name).Tags) > 0 {
		return
	}
	os.Remove(s.repoPath(name))
	os.Remove(filepath.Dir(s.repoPath(name)))
	delete(s.load, name)
}
