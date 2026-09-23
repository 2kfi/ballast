package main

import (
	"encoding/json"
	"net/http"
	"os"
	"time"
)

const uiHTML = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ballast</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#111}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.9rem}
th{background:#f5f5f5}code{font-size:.85em}.muted{color:#666}.badge{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.75rem}
.frozen{background:#e6f4ea}.floating{background:#fef7e0}.top{display:flex;justify-content:space-between;align-items:baseline}
input{padding:.4rem .6rem;width:240px}</style></head><body>
<div class="top"><h1>ballast</h1><span class="muted" id="stats"></span></div>
<p class="muted">Read-only mirror browser. Frozen = immutable snapshot under prefix. Floating = revalidated on TTL.</p>
<input id="q" placeholder="filter repos…" oninput="render()">
<table><thead><tr><th>repo</th><th>tag</th><th>digest</th><th>type</th><th>updated</th></tr></thead><tbody id="rows"></tbody></table>
<script>let D=[];
async function load(){const r=await fetch('/api/repos');D=await r.json();
document.getElementById('stats').textContent=D.stats||'';
render()}
function render(){const q=document.getElementById('q').value.toLowerCase();
const tb=document.getElementById('rows');tb.innerHTML='';
(D.repos||[]).forEach(repo=>{if(repo.name.toLowerCase().includes(q)){
repo.tags.forEach(t=>{const tr=document.createElement('tr');
tr.innerHTML='<td><code>'+repo.name+'</code></td><td><code>'+t.tag+'</code></td><td class="muted"><code>'+t.digest.slice(0,19)+'…</code></td><td><span class="badge '+(t.frozen?'frozen':'floating')+'">'+(t.frozen?'frozen':'floating')+'</span></td><td class="muted">'+t.age+'</td>';
tb.appendChild(tr)})}})}
load()</script></body></html>`

type uiTag struct {
	Tag    string `json:"tag"`
	Digest string `json:"digest"`
	Frozen bool   `json:"frozen"`
	Age    string `json:"age"`
}

type uiRepo struct {
	Name string  `json:"name"`
	Tags []uiTag `json:"tags"`
}

func (srv *Server) uiIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
	w.Write([]byte(uiHTML))
}

func ageOf(unix int64) string {
	if unix == 0 {
		return "—"
	}
	d := time.Since(time.Unix(unix, 0))
	if d < time.Hour {
		return "just now"
	}
	if d < 24*time.Hour {
		return time.Now().Truncate(time.Hour).Sub(time.Unix(unix, 0).Truncate(time.Hour)).String()
	}
	return time.Unix(unix, 0).Format("2006-01-02")
}

func (srv *Server) apiRepos(w http.ResponseWriter, r *http.Request) {
	srv.api(w)
	repos := srv.s.ListRepos()
	out := []uiRepo{}
	for _, name := range repos {
		tags := srv.s.ListTags(name)
		ur := uiRepo{Name: name}
		for _, t := range tags {
			e, ok := srv.s.GetTag(name, t)
			if !ok {
				continue
			}
			frozen := e.Frozen != "" || (len(name) > len(srv.cfg.Prefix)+1 && name[:len(srv.cfg.Prefix)+1] == srv.cfg.Prefix+"/")
			ur.Tags = append(ur.Tags, uiTag{Tag: t, Digest: e.Digest, Frozen: frozen, Age: ageOf(e.LastChecked)})
		}
		if len(ur.Tags) > 0 {
			out = append(out, ur)
		}
	}
	if out == nil {
		out = []uiRepo{}
	}
	blobs, bytes := srv.s.DiskUsage()
	stats := ""
	if hn, err := os.Hostname(); err == nil {
		stats = hn + " · "
	}
	stats += itoa(len(out)) + " repos · " + itoa(blobs) + " blobs · " + humanBytes(bytes)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"repos": out, "stats": stats})
}

func humanBytes(n int64) string {
	if n < 1024 {
		return itoa(int(n)) + " B"
	}
	if n < 1024*1024 {
		return itoa(int(n/1024)) + " KB"
	}
	if n < 1024*1024*1024 {
		return itoa(int(n/1024/1024)) + " MB"
	}
	return itoa(int(n/1024/1024/1024)) + " GB"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
