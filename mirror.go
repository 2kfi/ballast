package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

var versionTag = regexp.MustCompile(`^[vV]?\d`)

// debug logs only when BALLAST_DEBUG is set (read once at startup).
var debugOn = os.Getenv("BALLAST_DEBUG") != ""

func dbg(l *log.Logger, f string, a ...any) {
	if debugOn {
		l.Printf("DEBUG "+f, a...)
	}
}

func digestOfBytes(b []byte) (string, error) {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

func isDigest(ref string) bool { return strings.HasPrefix(ref, "sha256:") }

// classifyFloating: version-leading tags (3.12, 9-alpine) get the long TTL and
// freeze as-is; everything else (latest, stable, ...) is floating.
func classifyFloating(tag string) bool { return !versionTag.MatchString(tag) }

type ociProbe struct {
	MediaType string                  `json:"mediaType"`
	Manifests []json.RawMessage       `json:"manifests"`
	Config    struct{ Digest string } `json:"config"`
	Layers    []struct {
		Digest string   `json:"digest"`
		URLs   []string `json:"urls"`
	} `json:"layers"`
}

func sniffMediaType(b []byte) string {
	var p ociProbe
	if err := json.Unmarshal(b, &p); err == nil && p.MediaType != "" {
		return p.MediaType
	}
	if len(p.Manifests) > 0 {
		return "application/vnd.oci.image.index.v1+json"
	}
	return "application/vnd.oci.image.manifest.v1+json"
}

type mirror struct {
	cfg *Config
	s   *Store
	u   *upstreamClient
	log *log.Logger
}

func (m *mirror) frozenName(name string) string { return m.cfg.Prefix + "/" + name }

// liveManifest serves name:tag from the live/mirror namespace: local-fresh hits
// disk, expired or unknown tags revalidate against upstream.
func (m *mirror) liveManifest(name, tag string) (*tagEntry, error) {
	e, ok := m.s.GetTag(name, tag)
	if !ok {
		return m.prime(name, tag, false)
	}
	if e.UpstreamHost == "" {
		return e, nil // client-pushed repo, local only
	}
	ttl := m.cfg.duration("floating")
	if !e.Floating {
		ttl = m.cfg.duration("version")
	}
	if time.Now().Before(time.Unix(e.LastChecked, 0).Add(ttl)) {
		return e, nil
	}
	dbg(m.log, "revalidating %s:%s (floating=%v ttl=%s)", name, tag, e.Floating, ttl)
	return m.revalidate(name, tag, e)
}

func (m *mirror) prime(name, tag string, hard bool) (*tagEntry, error) {
	if !validName(name) || !validTag(tag) {
		return nil, fmt.Errorf("invalid name/tag")
	}
	ref := resolveName(name)
	b, d, err := m.u.fetchManifest(ref, tag)
	if err != nil {
		return nil, err
	}
	if !validDigest(d) {
		return nil, fmt.Errorf("upstream returned invalid digest %q", d)
	}
	if _, _, err := m.s.PutBlob(bytes.NewReader(b), d); err != nil {
		return nil, err
	}
	mt := sniffMediaType(b)
	// prefetch the tree (index -> default platform -> config + layers) so the
	// frozen copy is a complete offline snapshot; other platforms fill in lazily.
	if err := m.prefill(ref, d, hard); err != nil && hard {
		return nil, err
	}
	e := &tagEntry{
		Digest: d, MediaType: mt,
		UpstreamHost: ref.host, UpstreamPath: ref.path,
		Floating: classifyFloating(tag), LastChecked: time.Now().Unix(),
	}
	if e.Floating {
		if concrete := m.resolveConcrete(ref, d); concrete != "" {
			e.Frozen = concrete
		}
	} else {
		e.Frozen = tag
	}
	if err := m.s.SetTag(name, tag, e); err != nil {
		return nil, err
	}
	if e.Frozen != "" {
		if err := m.s.SetFrozen(m.frozenName(name), e.Frozen, d, mt); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func (m *mirror) revalidate(name, tag string, e *tagEntry) (*tagEntry, error) {
	// e is already a deep copy from GetTag; safe to mutate.
	ref := manifestRef{host: e.UpstreamHost, path: e.UpstreamPath}
	b, d, err := m.u.fetchManifest(ref, tag)
	if err != nil {
		m.log.Printf("revalidate %s:%s failed (%v); serving cached copy", name, tag, err)
		e.LastChecked = time.Now().Unix()
		m.s.SetTag(name, tag, e)
		return e, nil
	}
	if !validDigest(d) {
		return e, fmt.Errorf("upstream invalid digest %q", d)
	}
	if d == e.Digest {
		e.LastChecked = time.Now().Unix()
		m.s.SetTag(name, tag, e)
		if e.Frozen != "" {
			// frozen tag deleted but live still points here: restore snapshot
			if _, ok := m.s.GetTag(m.frozenName(name), e.Frozen); !ok {
				m.s.SetFrozen(m.frozenName(name), e.Frozen, d, e.MediaType)
			}
		}
		return e, nil
	}
	if _, _, err := m.s.PutBlob(bytes.NewReader(b), d); err != nil {
		return nil, err
	}
	mt := sniffMediaType(b)
	ne := &tagEntry{
		Digest: d, MediaType: mt,
		UpstreamHost: e.UpstreamHost, UpstreamPath: e.UpstreamPath,
		Floating: e.Floating, LastChecked: time.Now().Unix(),
	}
	if e.Floating {
		if concrete := m.resolveConcrete(ref, d); concrete != "" {
			ne.Frozen = concrete
		}
	} else {
		ne.Frozen = tag
	}
	// Only delete old frozen AFTER new one is persisted (never leave none).
	if ne.Frozen != "" {
		if err := m.s.SetFrozen(m.frozenName(name), ne.Frozen, d, mt); err != nil {
			return nil, err
		}
		if e.Frozen != "" && e.Frozen != ne.Frozen {
			_ = m.s.DelTag(m.frozenName(name), e.Frozen)
		}
	}
	m.s.SetTag(name, tag, ne)
	m.prefill(ref, d, false)
	return ne, nil
}

// resolveConcrete scans upstream tags to find the version tag sharing digest
// (latest -> 3.14.0, 9-alpine -> 9.2.2-alpine). "" means digest-pin via @sha256.
func (m *mirror) resolveConcrete(ref manifestRef, digest string) string {
	if !validDigest(digest) {
		return ""
	}
	tags, err := m.u.listTags(ref)
	if err != nil {
		m.log.Printf("tags/list %s/%s failed: %v", ref.host, ref.path, err)
		return ""
	}
	best, bestDots, bestLen := "", -1, -1
	checked := 0
	for _, t := range tags {
		if len(t) < 2 || classifyFloating(t) || !validTag(t) {
			continue // skip latest/stable etc; only version-shaped candidates
		}
		if checked >= 50 { // cap N+1 storm (python has 1000s of tags)
			break
		}
		checked++
		if _, d, err := m.u.fetchManifest(ref, t); err == nil && d == digest {
			dots, ln := strings.Count(t, "."), len(t)
			if dots > bestDots || (dots == bestDots && ln > bestLen) {
				best, bestDots, bestLen = t, dots, ln
			}
		}
	}
	if best == "" {
		m.log.Printf("no concrete tag matches %s/%s digest %s; freezing by digest", ref.host, ref.path, digest)
	}
	return best
}

// prefill pulls the default-platform manifest tree (config + layers) for digest.
// soft failure keeps service up (live lazy-fill covers gaps); hard is for the CLI.
func (m *mirror) prefill(ref manifestRef, top string, hard bool) error {
	return m.prefillVisit(ref, top, hard, map[string]bool{}, 0)
}

func (m *mirror) prefillVisit(ref manifestRef, top string, hard bool, seen map[string]bool, depth int) error {
	fail := func(err error) error {
		if hard {
			return err
		}
		m.log.Printf("prefill %s/%s %s partial: %v", ref.host, ref.path, top, err)
		return nil
	}
	if !validDigest(top) {
		return fail(fmt.Errorf("invalid digest %q", top))
	}
	if seen[top] {
		return fail(fmt.Errorf("cycle at %s", top))
	}
	seen[top] = true
	if depth > 3 {
		return fail(fmt.Errorf("index depth exceeded"))
	}
	b, err := os.ReadFile(m.s.blobPath(top))
	if err != nil {
		return fail(err)
	}
	if int64(len(b)) > maxManifestBytes {
		return fail(fmt.Errorf("manifest too large"))
	}
	var p ociProbe
	if err := json.Unmarshal(b, &p); err != nil {
		return fail(err)
	}
	if len(p.Manifests) > 0 { // index/list -> pick default platform
		os_, arch := m.platform()
		for _, raw := range p.Manifests {
			var e struct {
				Digest   string `json:"digest"`
				Platform struct {
					OS           string `json:"os"`
					Architecture string `json:"architecture"`
				} `json:"platform"`
			}
			if json.Unmarshal(raw, &e) != nil || !validDigest(e.Digest) {
				continue
			}
			if e.Platform.OS == os_ && e.Platform.Architecture == arch {
				return m.prefillVisit(ref, e.Digest, hard, seen, depth+1)
			}
		}
		return fail(fmt.Errorf("no %s/%s platform in index", os_, arch))
	}
	return m.prefillLayers(ref, p)
}

func (m *mirror) prefillLayers(ref manifestRef, p ociProbe) error {
	for _, d := range digestSet(p) {
		if m.s.HasBlob(d) {
			continue
		}
		if err := m.fetchUpstreamBlob(ref, d); err != nil {
			return err
		}
	}
	return nil
}

func digestSet(p ociProbe) []string {
	var ds []string
	if validDigest(p.Config.Digest) {
		ds = append(ds, p.Config.Digest)
	}
	for _, l := range p.Layers {
		if validDigest(l.Digest) && len(l.URLs) == 0 { // foreign layers served externally
			ds = append(ds, l.Digest)
		}
	}
	return ds
}

func (m *mirror) fetchUpstreamBlob(ref manifestRef, digest string) error {
	if !validDigest(digest) {
		return fmt.Errorf("invalid digest %q", digest)
	}
	f, err := os.CreateTemp(m.s.root+"/tmp", "blob")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := m.u.fetchBlob(ref, digest, f); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := m.s.PutBlobFromFile(f.Name(), digest); err != nil {
		// Surface verification failures; only ignore already-exists races.
		if m.s.HasBlob(digest) {
			return nil
		}
		return err
	}
	return nil
}

func (m *mirror) platform() (string, string) {
	p := m.cfg.DefaultPlatform
	if i := strings.Index(p, "/"); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "linux", p
}
