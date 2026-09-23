package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var cliClient = &http.Client{Timeout: 30 * time.Second}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	if len(os.Args) < 2 {
		die("usage: ballast serve|pull|rm|gc|hash [flags]")
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "pull":
		cmdPull(os.Args[2:])
	case "rm":
		cmdRm(os.Args[2:])
	case "gc":
		cmdGC(os.Args[2:])
	case "hash":
		cmdHash(os.Args[2:])
	default:
		die("usage: ballast serve|pull|rm|gc|hash [flags]")
	}
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "ballast.json", "config file")
	fs.Parse(args)

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		die("%v", err)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		die("%v", err)
	}
	log.Printf("listening on %s (storage %s, prefix %q)", cfg.Addr, cfg.Storage, cfg.Prefix)
	log.Printf("TTL: version %s, floating %s", cfg.duration("version"), cfg.duration("floating"))
	if cfg.AllowAnonymous {
		log.Printf("WARNING: allowAnonymous=true — anonymous reads enabled")
	}
	if !cfg.BehindProxy && !isLocalAddr(cfg.Addr) {
		log.Printf("WARNING: serving on non-localhost without behindProxy; put TLS reverse-proxy in front")
	}

	h := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       90 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		h.Shutdown(context.Background())
	}()
	if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		die("%v", err)
	}
}

// ballast pull python:3.12  ->  primes the live mirror + frozen copy via our own server
func cmdPull(args []string) {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	cfgPath := fs.String("config", "ballast.json", "config file")
	addr := fs.String("addr", "", "registry address (defaults to config addr)")
	user := fs.String("user", "admin", "registry basic-auth user")
	token := fs.String("token", "", "registry token")
	fs.Parse(args)
	if fs.NArg() != 1 {
		die("usage: ballast pull <image>[:tag]")
	}
	ref := fs.Arg(0)
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		die("%v", err)
	}
	if *addr == "" {
		*addr = cfg.Addr
	}

	name, tag := splitRef(ref)
	base := "http://" + *addr
	d, err := apiGet(base, *user, *token, "/v2/"+name+"/manifests/"+tag)
	if err != nil {
		die("%v", err)
	}
	fmt.Printf("live   : %s/%s:%s  -> %s\n", *addr, name, tag, d)

	// find the frozen tag just created
	frozen := cfg.Prefix + "/" + name
	out, err := apiList(base, *user, *token, "/v2/"+frozen+"/tags/list")
	if err != nil {
		die("%v", err)
	}
	if len(out) == 0 {
		fmt.Printf("frozen : (floating tag, no concrete version upstream; pull by digest)\n  %s/%s@%s\n", *addr, frozen, d)
		return
	}
	for _, t := range out {
		fmt.Printf("frozen : %s/%s:%s\n", *addr, frozen, t)
	}
}

// ballast rm <image>[:tag] removes live + frozen tags (blobs stay, prune later)
func cmdRm(args []string) {
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	cfgPath := fs.String("config", "ballast.json", "config file")
	fs.Parse(args)
	if fs.NArg() != 1 {
		die("usage: ballast rm <image>[:tag]")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		die("%v", err)
	}
	s, err := openStore(cfg.Storage)
	if err != nil {
		die("%v", err)
	}
	name, tag := splitRef(fs.Arg(0))
	if !validName(name) || (!validTag(tag) && !validDigest(tag)) {
		die("invalid ref: %s", fs.Arg(0))
	}
	e, ok := s.GetTag(name, tag)
	if !ok {
		die("tag not found: %s:%s", name, tag)
	}
	if err := s.DelTag(name, tag); err != nil {
		die("rm: %v", err)
	}
	if e.Frozen != "" {
		_ = s.DelTag(cfg.Prefix+"/"+name, e.Frozen)
		fmt.Printf("removed %s:%s and frozen %s:%s\n", name, tag, cfg.Prefix+"/"+name, e.Frozen)
		return
	}
	fmt.Printf("removed %s:%s\n", name, tag)
}

// splitRef splits "registry/path:tag" or "path@digest" into storage name + tag/digest.
func splitRef(ref string) (string, string) {
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return ref, "latest"
	}
	// Don't confuse host:port with tag (e.g. localhost:5000/img without tag).
	slash := strings.LastIndex(ref, "/")
	if slash > i {
		return ref, "latest"
	}
	return ref[:i], ref[i+1:]
}

func isLocalAddr(addr string) bool {
	return strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "localhost:") ||
		strings.HasPrefix(addr, ":") || strings.HasPrefix(addr, "[::1]")
}

func apiGet(base, user, token, path string) (string, error) {
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", manifestAccept)
	req.SetBasicAuth(user, token)
	resp, err := cliClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return "", fmt.Errorf("unauthorized (wrong --user/--token?)")
		}
		return "", fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return resp.Header.Get("Docker-Content-Digest"), nil
}

func apiList(base, user, token, path string) ([]string, error) {
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, token)
	resp, err := cliClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("GET %s: %s %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	var out struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Tags, nil
}

// ballast hash <token> prints a salted "salt:hex" verifier for users_sha256.
func cmdHash(args []string) {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		die("usage: ballast hash <token>")
	}
	salt, err := newSalt()
	if err != nil {
		die("rand: %v", err)
	}
	fmt.Println(hashToken(fs.Arg(0), salt))
}

// ballast gc [--apply] removes unreferenced blobs.
func cmdGC(args []string) {
	fs := flag.NewFlagSet("gc", flag.ExitOnError)
	cfgPath := fs.String("config", "ballast.json", "config file")
	apply := fs.Bool("apply", false, "delete (default dry-run)")
	fs.Parse(args)
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		die("%v", err)
	}
	s, err := openStore(cfg.Storage)
	if err != nil {
		die("%v", err)
	}
	referenced := map[string]bool{}
	for _, repo := range s.ListRepos() {
		for _, t := range s.ListTags(repo) {
			e, ok := s.GetTag(repo, t)
			if !ok || !validDigest(e.Digest) {
				continue
			}
			referenced[e.Digest] = true
			// One level: config + layers inside the manifest.
			if p, ok := s.GetBlob(e.Digest); ok {
				if b, err := os.ReadFile(p); err == nil {
					var probe struct {
						Config struct {
							Digest string `json:"digest"`
						} `json:"config"`
						Layers []struct {
							Digest string `json:"digest"`
						} `json:"layers"`
					}
					if json.Unmarshal(b, &probe) == nil {
						if validDigest(probe.Config.Digest) {
							referenced[probe.Config.Digest] = true
						}
						for _, l := range probe.Layers {
							if validDigest(l.Digest) {
								referenced[l.Digest] = true
							}
						}
					}
				}
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(cfg.Storage, "blobs", "sha256"))
	if err != nil {
		die("read blobs: %v", err)
	}
	var orphan []string
	var orphanBytes int64
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		d := "sha256:" + de.Name()
		if !validDigest(d) || referenced[d] {
			continue
		}
		if info, err := de.Info(); err == nil {
			orphanBytes += info.Size()
		}
		orphan = append(orphan, d)
	}
	fmt.Printf("%d orphan blobs, %.1f MB\n", len(orphan), float64(orphanBytes)/1e6)
	if !*apply {
		fmt.Println("(dry-run; re-run with --apply to delete)")
		for _, d := range orphan {
			fmt.Println("  " + d)
		}
		return
	}
	for _, d := range orphan {
		if err := s.DelBlob(d); err != nil {
			fmt.Printf("del %s: %v\n", d, err)
		} else {
			fmt.Printf("deleted %s\n", d)
		}
	}
}

func die(f string, a ...any) {
	log.Printf(f, a...)
	os.Exit(1)
}
