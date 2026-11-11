// Command ja4dbgen rebuilds data/ja4db.json from the JA4DB fingerprint
// snapshot (the only openly redistributable copy of the JA4DB dataset).
//
// JA4DB (ja4db.com / now ja4db.foxio.io) is no longer open access, but a
// frozen snapshot of the public API (2026-05-15) is mirrored on GitHub at
// github.com/Niicolaa/ja4db-export (daily-export workflow that stopped
// producing data). This generator consumes that snapshot's
// csv/ja4_fingerprint.csv and compacts the 74k observation rows into a
// per-fingerprint summary: observation count, named applications, and a few
// representative User-Agent strings (deduplicated, truncated) so the server
// can vote on the client from UA evidence at runtime.
//
// Usage:
//
//	go run ./tools/ja4dbgen [-in /path/to/ja4_fingerprint.csv] [-out data/ja4db.json]
//
// Without -in, the script downloads the snapshot CSV (jsdelivr CDN first, raw
// GitHub as fallback) and caches it under tools/ja4dbgen/cache/.
//
// Output format (data/ja4db.json):
//
//	{
//	  "meta": { "source": "...", "exported": "2026-05-15", "generated": "...",
//	             "entries": 1573, "observations": 319735 },
//	  "ja4": {
//	    "t13d1516h2_8daaf6152771_d8a2da3f94cd": {
//	      "n": 35849, "v": 0,
//	      "apps": [["Chrome", 3]],
//	      "uas": [[524, "Mozilla/5.0 ... Chrome/143.0.0.0 Safari/537.36"], ...]
//	    }
//	  }
//	}
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	snapshotURL   = "https://cdn.jsdelivr.net/gh/Niicolaa/ja4db-export@main/csv/ja4_fingerprint.csv"
	snapshotURL2  = "https://raw.githubusercontent.com/Niicolaa/ja4db-export/main/csv/ja4_fingerprint.csv"
	exportedDate  = "2026-05-15"
	defaultOutDir = "data"
)

// ja4Re validates the FoxIO JA4 fingerprint shape for TLS-over-TCP hellos and
// normalizes whitespace: t<TLS version><sni flag><2-digit cipher count>
// <2-digit extension count><2-char ALPN>_<12 hex>_<12 hex>.
var ja4Re = regexp.MustCompile(`^t(1[0-3]|s[23])[di][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

type entry struct {
	N    uint64   `json:"n"`              // summed observation_count
	V    uint64   `json:"v,omitempty"`    // rows marked verified
	Apps [][2]any `json:"apps,omitempty"` // [[name, count], ...]
	Libs [][2]any `json:"libs,omitempty"`
	OSes [][2]any `json:"os,omitempty"`
	UAs  [][2]any `json:"uas"` // [[count, user_agent], ...] top shapes
}

func main() {
	in := flag.String("in", "", "local ja4_fingerprint.csv (empty = download the snapshot)")
	out := flag.String("out", "", "output JSON path (default data/ja4db.json)")
	maxUA := flag.Int("max-uas", 8, "keep at most this many UA strings per fingerprint")
	flag.Parse()

	if *out == "" {
		*out = filepath.Join(defaultOutDir, "ja4db.json")
	}

	var path string
	if *in != "" {
		path = *in
	} else {
		cacheDir := filepath.Join("tools", "ja4dbgen", "cache")
		os.MkdirAll(cacheDir, 0o755)
		path = filepath.Join(cacheDir, "ja4_fingerprint.csv")
		if _, err := os.Stat(path); err != nil {
			if err := download(snapshotURL, path); err != nil {
				log.Printf("primary mirror failed (%v); trying raw.githubusercontent", err)
				if err2 := download(snapshotURL2, path); err2 != nil {
					log.Fatalf("could not download snapshot from either mirror: %v", err2)
				}
			}
		}
	}

	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	r := csv.NewReader(bufio.NewReaderSize(f, 1<<20))
	header, err := r.Read()
	if err != nil {
		log.Fatal(err)
	}
	col := make(map[string]int, len(header))
	for i, h := range header {
		col[h] = i
	}
	for _, need := range []string{"application", "library", "device", "os",
		"user_agent_string", "verified", "observation_count", "ja4_fingerprint"} {
		if _, ok := col[need]; !ok {
			log.Fatalf("column %q missing from %s", need, path)
		}
	}

	type agg struct {
		n, v                  uint64
		apps, libs, oses, uas map[string]uint64
	}
	byFP := map[string]*agg{}
	var rows, skipped, obs uint64

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("csv parse error: %v", err)
		}
		rows++
		fp := strings.TrimSpace(rec[col["ja4_fingerprint"]])
		if !ja4Re.MatchString(fp) {
			skipped++
			continue
		}
		obs++
		a := byFP[fp]
		if a == nil {
			a = &agg{
				apps: map[string]uint64{}, libs: map[string]uint64{},
				oses: map[string]uint64{}, uas: map[string]uint64{},
			}
			byFP[fp] = a
		}
		var n uint64 = 1
		fmt.Sscanf(rec[col["observation_count"]], "%d", &n)
		a.n += n
		if strings.TrimSpace(rec[col["verified"]]) == "true" {
			a.v++
		}
		add := func(m map[string]uint64, s string) {
			if s = strings.TrimSpace(s); s != "" {
				m[s]++
			}
		}
		add(a.apps, rec[col["application"]])
		add(a.libs, rec[col["library"]])
		add(a.oses, rec[col["os"]])
		if ua := strings.TrimSpace(rec[col["user_agent_string"]]); ua != "" {
			if len(ua) > 200 {
				ua = ua[:200] + "…"
			}
			a.uas[ua]++
		}
	}

	log.Printf("read %d rows, kept %d (skipped %d non-TCP/invalid), %d unique fingerprints", rows, obs, skipped, len(byFP))

	// Sort entries for reproducible output, cap UA list.
	type kv struct {
		fp string
		a  *agg
	}
	sorted := make([]kv, 0, len(byFP))
	for fp, a := range byFP {
		sorted = append(sorted, kv{fp, a})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].fp < sorted[j].fp })

	top := func(m map[string]uint64, n int) [][2]any {
		type pc struct {
			name  string
			count uint64
		}
		lst := make([]pc, 0, len(m))
		for k, v := range m {
			lst = append(lst, pc{k, v})
		}
		sort.Slice(lst, func(i, j int) bool {
			if lst[i].count != lst[j].count {
				return lst[i].count > lst[j].count
			}
			return lst[i].name < lst[j].name
		})
		if len(lst) > n {
			lst = lst[:n]
		}
		out := make([][2]any, 0, len(lst))
		for _, p := range lst {
			out = append(out, [2]any{p.name, p.count})
		}
		return out
	}

	outDoc := struct {
		Meta map[string]any    `json:"meta"`
		JA4  map[string]*entry `json:"ja4"`
	}{Meta: map[string]any{}, JA4: map[string]*entry{}}
	outDoc.Meta["source"] = "JA4DB (ja4db.com) frozen public-API snapshot of " + exportedDate +
		", mirrored by github.com/Niicolaa/ja4db-export"
	outDoc.Meta["exported"] = exportedDate
	outDoc.Meta["generated"] = time.Now().UTC().Format("2006-01-02")
	outDoc.Meta["entries"] = len(sorted)
	outDoc.Meta["observations"] = obs

	for _, kv := range sorted {
		e := &entry{N: kv.a.n, V: kv.a.v, UAs: top(kv.a.uas, *maxUA)}
		if len(kv.a.apps) > 0 {
			e.Apps = top(kv.a.apps, 5)
		}
		if len(kv.a.libs) > 0 {
			e.Libs = top(kv.a.libs, 5)
		}
		if len(kv.a.oses) > 0 {
			e.OSes = top(kv.a.oses, 5)
		}
		outDoc.JA4[kv.fp] = e
	}

	os.MkdirAll(filepath.Dir(*out), 0o755)
	raw, err := json.Marshal(outDoc)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s (%d bytes)", *out, len(raw))
}

func download(url, path string) error {
	log.Printf("downloading %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}
