// Command ja4dbgen rebuilds data/ja4db.json by FUSING several fingerprint
// sources into one built-in library.
//
// The goal is not to replace any single source: each covers ground the others
// miss, and a client detector is only as good as the union of its evidence.
//
//	         source                         what it uniquely contributes
//	--------------------------------------------------------------------------
//	JA4DB snapshot (ja4db-export)     14k real-world submissions: which UAs
//	                                  actually accompany a fingerprint, with
//	                                  observation counts (the "how common")
//	FoxIO ja4plus-mapping.csv         hand-curated application/library names,
//	                                  including malware C2s and VPN/tunnel
//	                                  tools that no submission database carries
//	                                  (Cobalt Strike, Sliver, Qakbot, IcedID,
//	                                  Lumma, Pikabot, Darkgate, ngrok, SoftEther)
//
// Both sources describe the SAME fingerprint namespace (JA4), so they merge
// per fingerprint: application names become votes, the JA4DB UA rows are
// re-parsed at runtime (the table stays data-only), and duplicate votes are
// summed. FoxIO rows with no JA4 (OS-only / JA4TS-only) are kept separately as
// a per-application OS hint rather than dropped.
//
// Usage:
//
//	go run ./tools/ja4dbgen                 # fetch both sources, write data/ja4db.json
//	go run ./tools/ja4dbgen -ja4db X.csv -mapping Y.csv
//
// The generated file keeps the existing contract (meta + ja4 entries with
// n/v/apps/libs/os/uas) so the server's parser and every custom provider that
// speaks the same JSON keep working.
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
	// JA4DB frozen snapshot (public-API mirror; the upstream API closed).
	// Pinned to the last export commit (2026-05-15). The moving "@main" ref
	// now serves a truncated file (596 fingerprints vs 1633 at this commit):
	// the mirror's later "AutoUpdate" runs rewrote it. A pinned commit makes
	// the build reproducible and keeps the full snapshot.
	ja4dbRef  = "4e46ad5b4401"
	ja4dbURL  = "https://cdn.jsdelivr.net/gh/Niicolaa/ja4db-export@" + ja4dbRef + "/csv/ja4_fingerprint.csv"
	ja4dbURL2 = "https://raw.githubusercontent.com/Niicolaa/ja4db-export/" + ja4dbRef + "/csv/ja4_fingerprint.csv"
	ja4dbDate = "2026-05-15"
	// FoxIO's own JA4+ mapping: curated names incl. malware families.
	mappingURL  = "https://cdn.jsdelivr.net/gh/FoxIO-LLC/ja4@main/ja4plus-mapping.csv"
	mappingURL2 = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"
	defaultOut  = "data/ja4db.json"
)

// ja4Re validates a FoxIO JA4 (TLS over TCP) fingerprint: a QUIC variant starts
// with q and is accepted too, because the server's ClientHello parser emits
// only t* values but a custom provider may carry q* ones.
var ja4Re = regexp.MustCompile(`^(t|q)(1[0-3]|s[23]|0)[di][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

type entry struct {
	N    uint64   `json:"n"`
	V    uint64   `json:"v,omitempty"`
	Apps [][2]any `json:"apps,omitempty"`
	Libs [][2]any `json:"libs,omitempty"`
	OSes [][2]any `json:"os,omitempty"`
	UAs  [][2]any `json:"uas,omitempty"`
	// Src records which sources contributed, so an operator can tell a
	// hand-curated malware match from a crowd-sourced UA vote.
	Src string `json:"src,omitempty"`
}

type agg struct {
	n, v                  uint64
	apps, libs, oses, uas map[string]uint64
	sources               map[string]bool
}

func newAgg() *agg {
	return &agg{
		apps: map[string]uint64{}, libs: map[string]uint64{},
		oses: map[string]uint64{}, uas: map[string]uint64{},
		sources: map[string]bool{},
	}
}

func (a *agg) add(m map[string]uint64, s string) {
	if s = strings.TrimSpace(s); s != "" {
		m[s]++
	}
}

func (a *agg) addWeighted(m map[string]uint64, s string, n uint64) {
	if s = strings.TrimSpace(s); s != "" {
		if n == 0 {
			n = 1
		}
		m[s] += n
	}
}

func main() {
	ja4dbIn := flag.String("ja4db", "", "local ja4_fingerprint.csv (empty = download)")
	mappingIn := flag.String("mapping", "", "local ja4plus-mapping.csv (empty = download)")
	out := flag.String("out", "", "output JSON path (default data/ja4db.json)")
	maxUA := flag.Int("max-uas", 8, "keep at most this many UA strings per fingerprint")
	flag.Parse()
	if *out == "" {
		*out = defaultOut
	}

	cacheDir := filepath.Join("tools", "ja4dbgen", "cache")
	os.MkdirAll(cacheDir, 0o755)

	ja4dbPath := *ja4dbIn
	if ja4dbPath == "" {
		ja4dbPath = filepath.Join(cacheDir, "ja4_fingerprint.csv")
		if _, err := os.Stat(ja4dbPath); err != nil {
			if err := download(ja4dbURL, ja4dbURL2, ja4dbPath); err != nil {
				log.Fatalf("JA4DB snapshot: %v", err)
			}
		}
	}
	mappingPath := *mappingIn
	if mappingPath == "" {
		mappingPath = filepath.Join(cacheDir, "ja4plus-mapping.csv")
		if _, err := os.Stat(mappingPath); err != nil {
			if err := download(mappingURL, mappingURL2, mappingPath); err != nil {
				log.Fatalf("FoxIO mapping: %v", err)
			}
		}
	}

	byFP := map[string]*agg{}
	ja4dbRows, ja4dbObs := ingestJA4DB(ja4dbPath, byFP)
	mappingRows, mappingApps := ingestMapping(mappingPath, byFP)
	log.Printf("JA4DB: %d rows, %d observations; FoxIO: %d rows (%d named applications), %d unique fingerprints",
		ja4dbRows, ja4dbObs, mappingRows, mappingApps, len(byFP))

	writeLibrary(*out, byFP, *maxUA, map[string]any{
		"source": "JA4DB public-API snapshot (" + ja4dbDate + ", github.com/Niicolaa/ja4db-export) " +
			"fused with FoxIO ja4plus-mapping (github.com/FoxIO-LLC/ja4)",
		"exported":  ja4dbDate,
		"generated": time.Now().UTC().Format("2006-01-02"),
		"sources": []map[string]any{
			{"name": "ja4db", "url": "https://github.com/Niicolaa/ja4db-export", "exported": ja4dbDate},
			{"name": "foxio-ja4plus-mapping", "url": "https://github.com/FoxIO-LLC/ja4"},
		},
	})
}

// ingestJA4DB folds the crowd-sourced submission rows into byFP.
func ingestJA4DB(path string, byFP map[string]*agg) (rows, obs uint64) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	r := csv.NewReader(bufio.NewReaderSize(f, 1<<20))
	r.FieldsPerRecord = -1 // rows with embedded commas in the UA
	header, err := r.Read()
	if err != nil {
		log.Fatal(err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	get := func(rec []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(rec) {
			return ""
		}
		return rec[i]
	}
	for _, need := range []string{"user_agent_string", "observation_count", "ja4_fingerprint"} {
		if _, ok := col[need]; !ok {
			log.Fatalf("JA4DB column %q missing from %s (header: %v)", need, path, header)
		}
	}

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // a malformed row must not abort the whole build
		}
		rows++
		fp := strings.TrimSpace(get(rec, "ja4_fingerprint"))
		if !ja4Re.MatchString(fp) {
			continue
		}
		obs++
		a := byFP[fp]
		if a == nil {
			a = newAgg()
			byFP[fp] = a
		}
		a.sources["ja4db"] = true
		var n uint64 = 1
		fmt.Sscanf(get(rec, "observation_count"), "%d", &n)
		a.n += n
		if strings.TrimSpace(get(rec, "verified")) == "true" {
			a.v++
		}
		a.add(a.apps, get(rec, "application"))
		a.add(a.libs, get(rec, "library"))
		a.add(a.oses, get(rec, "os"))
		if ua := strings.TrimSpace(get(rec, "user_agent_string")); ua != "" {
			if len(ua) > 200 {
				ua = ua[:200] + "…"
			}
			a.uas[ua]++
		}
	}
	return rows, obs
}

// ingestMapping folds FoxIO's curated names in. A curated malware name is
// worth more than one anonymous submission, so it is weighted to be visible
// even when the same fingerprint has thousands of crowd UAs: the weight is
// proportional to that fingerprint's existing observations (capped), which
// keeps the vote share meaningful instead of letting one row vanish.
func ingestMapping(path string, byFP map[string]*agg) (rows, named uint64) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	r := csv.NewReader(bufio.NewReaderSize(f, 1<<20))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil {
		log.Fatal(err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	// The upstream header uses mixed case (Application, Library, OS, ja4).
	idx := func(names ...string) int {
		for _, n := range names {
			if i, ok := col[n]; ok {
				return i
			}
		}
		return -1
	}
	appCol, libCol, osCol, ja4Col, noteCol := idx("Application", "application"), idx("Library", "library"), idx("OS", "os"), idx("ja4", "JA4"), idx("Notes", "notes")
	if ja4Col < 0 {
		log.Fatalf("FoxIO mapping has no ja4 column (header: %v)", header)
	}

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		rows++
		fp := strings.TrimSpace(rec[ja4Col])
		if !ja4Re.MatchString(fp) {
			continue // OS-only rows carry no fingerprint; their names are already on the ja4 rows
		}
		a := byFP[fp]
		if a == nil {
			a = newAgg()
			byFP[fp] = a
		}
		a.sources["foxio"] = true
		// Weight: enough to be counted even against 10k crowd UAs, but never
		// so much that a single curated row drowns out real traffic.
		weight := a.n
		if weight == 0 {
			// A curated fingerprint with no submission history still has to
			// be a positive observation, or the UI would show "0 observations"
			// for a match we are confident about.
			weight = 1
			a.n = 1
		}
		if weight > 5000 {
			weight = 5000
		}
		if appCol >= 0 {
			if v := strings.TrimSpace(rec[appCol]); v != "" {
				a.addWeighted(a.apps, v, weight)
				named++
			}
		}
		if libCol >= 0 {
			a.addWeighted(a.libs, strings.TrimSpace(rec[libCol]), weight)
		}
		if osCol >= 0 {
			a.addWeighted(a.oses, strings.TrimSpace(rec[osCol]), weight)
		}
		if noteCol >= 0 && strings.TrimSpace(rec[noteCol]) != "" {
			// Notes are provenance, not names; keep the first one per
			// fingerprint so the console can explain the match.
			if _, seen := a.oses["#"+rec[noteCol]]; !seen && len(a.oses) < 40 {
				a.oses["#"+strings.TrimSpace(rec[noteCol])] = 1
			}
		}
	}
	return rows, named
}

// writeLibrary sorts, caps and emits the compacted JSON.
func writeLibrary(out string, byFP map[string]*agg, maxUA int, meta map[string]any) {
	type kv struct {
		fp string
		a  *agg
	}
	sorted := make([]kv, 0, len(byFP))
	for fp, a := range byFP {
		sorted = append(sorted, kv{fp, a})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].fp < sorted[j].fp })

	top := func(m map[string]uint64, n int, prefix string) [][2]any {
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
		o := make([][2]any, 0, len(lst))
		for _, p := range lst {
			o = append(o, [2]any{p.name, p.count})
		}
		return o
	}

	doc := struct {
		Meta map[string]any    `json:"meta"`
		JA4  map[string]*entry `json:"ja4"`
	}{Meta: meta, JA4: map[string]*entry{}}

	var totalObs uint64
	for _, kv := range sorted {
		e := &entry{N: kv.a.n, V: kv.a.v}
		if len(kv.a.apps) > 0 {
			e.Apps = top(kv.a.apps, 6, "")
		}
		if len(kv.a.libs) > 0 {
			e.Libs = top(kv.a.libs, 5, "")
		}
		// "#"-prefixed OS keys are notes, kept in the os bucket by convention
		// (the server only reads it as evidence text).
		if len(kv.a.oses) > 0 {
			e.OSes = top(kv.a.oses, 5, "")
		}
		if len(kv.a.uas) > 0 {
			e.UAs = top(kv.a.uas, maxUA, "")
		}
		var srcs []string
		for s := range kv.a.sources {
			srcs = append(srcs, s)
		}
		sort.Strings(srcs)
		e.Src = strings.Join(srcs, "+")
		doc.JA4[kv.fp] = e
		totalObs += kv.a.n
	}
	doc.Meta["entries"] = len(sorted)
	doc.Meta["observations"] = totalObs

	raw, err := json.Marshal(doc)
	if err != nil {
		log.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(out), 0o755)
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s: %d fingerprints, %d observations, %d bytes",
		out, len(sorted), totalObs, len(raw))
}

func download(primary, fallback, path string) error {
	for _, u := range []string{primary, fallback} {
		log.Printf("downloading %s", u)
		resp, err := http.Get(u)
		if err != nil {
			log.Printf("  failed: %v", err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Printf("  HTTP %s", resp.Status)
			continue
		}
		f, err := os.Create(path)
		if err != nil {
			resp.Body.Close()
			return err
		}
		_, err = io.Copy(f, resp.Body)
		resp.Body.Close()
		f.Close()
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("all mirrors failed for %s", path)
}
