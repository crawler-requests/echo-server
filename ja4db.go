package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
)

// JA4DB integration: maps a ClientHello's JA4 fingerprint to the clients that
// have been observed using it. The dataset is a frozen snapshot of the public
// JA4DB database (see tools/ja4dbgen and data/ja4db.json) compacted into
// per-fingerprint evidence: how many observations, which applications were
// named by submitters, and a handful of representative User-Agent strings.
//
// Two lookup tiers keep this useful as the snapshot ages:
//
//  1. exact JA4 — the whole fingerprint, including the merged
//     extension+signature-algorithm hash;
//  2. JA4 prefix — the head and cipher hash only. Browsers rotate signature
//     algorithms and extensions with every release, so a new Chrome version
//     gets a new third field while its cipher list stays identical. Matching
//     the prefix still names it a Chrome-class client instead of failing.
//
// The UA strings are voted on at runtime with parseUserAgent, so the table
// stays data-only and the naming stays consistent with the header parser.

//go:embed data/ja4db.json
var ja4dbJSON []byte

// dbPair is one [label, count] pair in the generated JSON.
type dbPair struct {
	Label string
	Count uint64
}

func (p *dbPair) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil || len(raw) != 2 {
		return fmt.Errorf("ja4db: bad pair %s", string(b))
	}
	if err := json.Unmarshal(raw[0], &p.Label); err != nil {
		return err
	}
	return json.Unmarshal(raw[1], &p.Count)
}

type dbEntry struct {
	N    uint64   `json:"n"`
	V    uint64   `json:"v,omitempty"`
	Apps []dbPair `json:"apps,omitempty"`
	Libs []dbPair `json:"libs,omitempty"`
	OSes []dbPair `json:"os,omitempty"`
	UAs  []dbPair `json:"uas"`
}

type dbFile struct {
	Meta struct {
		Source       string `json:"source"`
		Exported     string `json:"exported"`
		Generated    string `json:"generated"`
		Entries      int    `json:"entries"`
		Observations int    `json:"observations"`
	} `json:"meta"`
	JA4 map[string]*dbEntry `json:"ja4"`
}

// dbVote is one client name's tally within a fingerprint's evidence.
type dbVote struct {
	name   string
	family string
	count  uint64
	verMin string // lowest major version observed ("137")
	verMax string // highest major version observed ("145")
	verRep string // representative full version ("137.0.0.0")
}

// dbAgg is the merged evidence for one fingerprint (exact) or for a whole
// JA4 prefix. Votes are computed once at start-up.
type dbAgg struct {
	obs      uint64
	verified uint64
	exact    bool
	votes    []dbVote // sorted by count desc
	named    uint64   // total weight that mapped to a known client name
	unparsed uint64   // weight of UA strings we cannot name (bots, junk)
}

type dbMeta struct {
	Source       string
	Exported     string
	Generated    string
	Entries      int
	Observations int
}

// ja4Lib is an immutable, compiled fingerprint library: per-fingerprint
// evidence indexed for exact and prefix lookup. One ja4Lib exists per
// provider (embedded snapshot, a local file, or a remote cloud library).
type ja4Lib struct {
	name     string
	meta     dbMeta
	exact    map[string]*dbAgg
	prefix   map[string]*dbAgg
	totalObs uint64
}

// ja4DB is the embedded snapshot, kept as the always-present fallback provider
// ("builtin"). Newer, custom libraries are layered on top by the dataset
// engine (the "ja4" dataset) and win over the snapshot by priority.
var ja4DB struct {
	ok     bool
	meta   dbMeta
	exact  map[string]*dbAgg
	prefix map[string]*dbAgg
}

// embeddedJA4Lib is compiled at start-up from the embedded snapshot and then
// attached to the dataset engine as the immutable "builtin" provider.
var embeddedJA4Lib *ja4Lib

func init() { loadJA4DB() }

// buildLib compiles a raw dbFile into lookup-indexed aggregates.
func buildLib(name string, f *dbFile) *ja4Lib {
	if f == nil || len(f.JA4) == 0 {
		return nil
	}
	lib := &ja4Lib{
		name: name,
		meta: dbMeta{
			Source: f.Meta.Source, Exported: f.Meta.Exported, Generated: f.Meta.Generated,
			Entries: f.Meta.Entries, Observations: f.Meta.Observations,
		},
		exact:  make(map[string]*dbAgg, len(f.JA4)),
		prefix: make(map[string]*dbAgg, len(f.JA4)),
	}
	if lib.meta.Entries == 0 {
		lib.meta.Entries = len(f.JA4)
	}
	for fp, e := range f.JA4 {
		a := aggregate(e, true)
		lib.exact[fp] = a
		lib.totalObs += a.obs
		pk := ja4Prefix(fp)
		p := lib.prefix[pk]
		if p == nil {
			p = &dbAgg{}
			lib.prefix[pk] = p
		}
		mergeAgg(p, a)
	}
	for _, a := range lib.prefix {
		finalizeAgg(a)
	}
	return lib
}

func loadJA4DB() {
	var f dbFile
	if err := json.Unmarshal(ja4dbJSON, &f); err != nil {
		log.Printf("ja4db: embedded database is unusable: %v", err)
		return
	}
	lib := buildLib("builtin", &f)
	if lib == nil {
		return
	}
	embeddedJA4Lib = lib
	// Convenience view for tests and diagnostics: the builtin layer only.
	ja4DB.ok = true
	ja4DB.meta = lib.meta
	ja4DB.exact = lib.exact
	ja4DB.prefix = lib.prefix
}

// aggregate turns raw evidence into votes. It is deterministic: candidates are
// sorted by weight and then by name.
func aggregate(f *dbEntry, exact bool) *dbAgg {
	a := &dbAgg{obs: f.N, verified: f.V, exact: exact}
	byName := map[string]*dbVote{}

	for _, p := range f.UAs {
		res := parseUserAgent(p.Label)
		if res.name == "" {
			a.unparsed += p.Count
			continue
		}
		v := byName[res.name]
		if v == nil {
			v = &dbVote{name: res.name, family: res.family}
			byName[res.name] = v
		}
		v.count += p.Count
		if res.version != "" {
			maj := majorVersion(res.version)
			if v.verRep == "" {
				v.verRep = res.version
			}
			if maj != "" {
				if v.verMin == "" || versionLess(maj, v.verMin) {
					v.verMin = maj
				}
				if v.verMax == "" || versionLess(v.verMax, maj) {
					v.verMax = maj
				}
			}
		}
	}
	// Named applications from the database carry weight: a submitter typed the
	// name in, so treat each app row as one observation (scaled to the entry's
	// average so a verified name is not drowned by thousands of anonymous UAs).
	for _, p := range f.Apps {
		name, version := splitAppLabel(p.Label)
		fam := familyForName(name)
		if name == "" || fam == "" {
			continue
		}
		v := byName[name]
		if v == nil {
			v = &dbVote{name: name, family: fam}
			byName[name] = v
		}
		v.count += p.Count
		if version != "" {
			maj := majorVersion(version)
			if v.verRep == "" {
				v.verRep = version
			}
			if v.verMin == "" || versionLess(maj, v.verMin) {
				v.verMin = maj
			}
			if v.verMax == "" || versionLess(v.verMax, maj) {
				v.verMax = maj
			}
		}
	}

	for _, v := range byName {
		a.votes = append(a.votes, *v)
	}
	finalizeAgg(a)
	return a
}

func finalizeAgg(a *dbAgg) {
	sort.Slice(a.votes, func(i, j int) bool {
		if a.votes[i].count != a.votes[j].count {
			return a.votes[i].count > a.votes[j].count
		}
		return a.votes[i].name < a.votes[j].name
	})
	a.named = 0
	for _, v := range a.votes {
		a.named += v.count
	}
}

// mergeAgg folds entry evidence into a prefix bucket.
func mergeAgg(dst, src *dbAgg) {
	dst.obs += src.obs
	dst.verified += src.verified
	dst.unparsed += src.unparsed
	byName := make(map[string]*dbVote, len(dst.votes))
	for _, v := range dst.votes {
		vv := v
		byName[v.name] = &vv
	}
	for _, v := range src.votes {
		cur := byName[v.name]
		if cur == nil {
			vv := v
			byName[v.name] = &vv
			continue
		}
		cur.count += v.count
		if cur.verRep == "" {
			cur.verRep = v.verRep
		}
		if v.verMin != "" && (cur.verMin == "" || versionLess(v.verMin, cur.verMin)) {
			cur.verMin = v.verMin
		}
		if v.verMax != "" && (cur.verMax == "" || versionLess(cur.verMax, v.verMax)) {
			cur.verMax = v.verMax
		}
	}
	dst.votes = dst.votes[:0]
	for _, v := range byName {
		dst.votes = append(dst.votes, *v)
	}
}

// ja4Prefix returns the version-independent part of a JA4: head + cipher hash.
func ja4Prefix(ja4 string) string {
	parts := strings.Split(ja4, "_")
	if len(parts) < 2 {
		return ja4
	}
	return parts[0] + "_" + parts[1]
}

// dbMatch is the outcome of a fingerprint-library lookup.
type dbMatch struct {
	Name         string
	Family       string
	Version      string
	Confidence   float64
	Candidates   []ClientCandidate
	Observations uint64
	Exact        bool
	Verified     bool
	Provider     string // provider name that supplied the match ("builtin", or a custom name)
	Note         string // e.g. "matched on the JA4 prefix (newer client build)"
}

// ClientCandidate is one plausible client for a fingerprint, with its share of
// the observations that could be named.
type ClientCandidate struct {
	Name   string  `json:"name"`
	Family string  `json:"family,omitempty"`
	Share  float64 `json:"share"` // 0..1 of named observations
}

// lookupJA4 returns the best evidence for a JA4 fingerprint across all
// configured providers: exact match first, then prefix match, in provider
// priority order (custom providers before the embedded snapshot).
func lookupJA4(ja4 string) *dbMatch {
	if ja4 == "" {
		return nil
	}
	if ja4Mgr == nil {
		// Dataset engine not initialised (embedded-only builds, tests that
		// exercise the snapshot in isolation): fall back to the compiled-in
		// library.
		if a := ja4DB.exact[ja4]; a != nil {
			return aggToMatch(a, true)
		}
		if a := ja4DB.prefix[ja4Prefix(ja4)]; a != nil {
			return aggToMatch(a, false)
		}
		return nil
	}
	set := ja4Mgr.Current()
	if set == nil || len(set.libs) == 0 {
		return nil
	}
	for _, lib := range set.libs {
		if a := lib.exact[ja4]; a != nil {
			if m := aggToMatch(a, true); m != nil {
				m.Provider = lib.name
				return m
			}
		}
	}
	pk := ja4Prefix(ja4)
	for _, lib := range set.libs {
		if a := lib.prefix[pk]; a != nil {
			if m := aggToMatch(a, false); m != nil {
				m.Provider = lib.name
				return m
			}
		}
	}
	return nil
}

// ja4LibSet is the runtime value of the "ja4" dataset: libraries in provider
// priority order (highest first, embedded snapshot last).
type ja4LibSet struct {
	libs []*ja4Lib
}

func aggToMatch(a *dbAgg, exact bool) *dbMatch {
	if a == nil || len(a.votes) == 0 || a.named == 0 {
		return nil
	}
	m := &dbMatch{
		Name:         a.votes[0].name,
		Family:       a.votes[0].family,
		Observations: a.obs,
		Exact:        exact,
		Verified:     a.verified > 0,
	}
	if m.Family == "" {
		m.Family = "unknown"
	}
	if v := a.votes[0]; v.verMin != "" {
		switch {
		case v.verMin == v.verMax && v.verRep != "":
			m.Version = v.verRep
		case v.verMin == v.verMax:
			m.Version = v.verMin
		default:
			m.Version = v.verMin + "-" + v.verMax
		}
	}
	for i, v := range a.votes {
		if i >= 4 {
			break
		}
		m.Candidates = append(m.Candidates, ClientCandidate{
			Name:   v.name,
			Family: v.family,
			Share:  round2(float64(v.count) / float64(a.named)),
		})
	}
	share := float64(a.votes[0].count) / float64(a.named)
	m.Confidence = dbConfidence(share, a.named, exact, a.verified > 0)
	if !exact {
		m.Note = "matched the JA4 prefix (head + cipher hash); the extension hash " +
			"is from a client build not present in the snapshot"
	}
	return m
}

// dbConfidence blends how clearly one client dominates the evidence with how
// much evidence there is at all. A single observation cannot be 95% certain.
func dbConfidence(share float64, named uint64, exact, verified bool) float64 {
	base := 0.62 + 0.34*share
	if !exact {
		base = 0.52 + 0.30*share
	}
	switch {
	case named <= 1:
		base *= 0.72
	case named <= 3:
		base *= 0.85
	case named <= 10:
		base *= 0.93
	}
	if verified {
		base += 0.02
	}
	if base > 0.95 {
		base = 0.95
	}
	if base < 0.3 {
		base = 0.3
	}
	return round2(base)
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

// splitAppLabel splits a database application label such as "Chrome 42.0" or
// "Samsung Internet 12" into a base name and an optional version.
func splitAppLabel(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	fields := strings.Fields(s)
	if len(fields) > 1 {
		if last := fields[len(fields)-1]; isPlainVersion(last) {
			return strings.Join(fields[:len(fields)-1], " "), last
		}
	}
	return s, ""
}

func isPlainVersion(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// familyForName maps an application label from the database to our families.
func familyForName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "":
		return ""
	case strings.Contains(n, "bot"), strings.Contains(n, "crawler"), strings.Contains(n, "spider"):
		return "bot"
	case strings.Contains(n, "chrome"), strings.Contains(n, "chromium"),
		strings.Contains(n, "edge"), strings.Contains(n, "opera"),
		strings.Contains(n, "brave"), strings.Contains(n, "vivaldi"),
		strings.Contains(n, "safari"), strings.Contains(n, "firefox"),
		strings.Contains(n, "samsung internet"), strings.Contains(n, "yandex"),
		strings.Contains(n, "uc browser"):
		return "browser"
	case strings.Contains(n, "curl"), strings.Contains(n, "wget"),
		strings.Contains(n, "openssl"), strings.Contains(n, "postman"):
		return "cli"
	case strings.Contains(n, "python"), strings.Contains(n, "requests"),
		strings.Contains(n, "aiohttp"), strings.Contains(n, "httpx"),
		strings.Contains(n, "okhttp"), strings.Contains(n, "axios"),
		strings.Contains(n, "java"), strings.Contains(n, "go"),
		strings.Contains(n, "node"):
		return "runtime"
	}
	return ""
}

// majorVersion returns the leading numeric component of a version string.
func majorVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	if _, err := strconv.Atoi(v); err != nil {
		return ""
	}
	return v
}

// versionLess compares two numeric major versions.
func versionLess(a, b string) bool {
	ai, err1 := strconv.Atoi(a)
	bi, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return a < b
	}
	return ai < bi
}

// ja4dbEvidence renders a human-readable evidence line for the client block.
func ja4dbEvidence(m *dbMatch) string {
	if m == nil {
		return ""
	}
	kind := "JA4 exact match"
	if !m.Exact {
		kind = "JA4 prefix match"
	}
	src := "JA4DB" // the embedded snapshot
	if m.Provider != "" && m.Provider != "builtin" {
		src = "JA4 provider " + m.Provider
	}
	parts := make([]string, 0, len(m.Candidates))
	for _, c := range m.Candidates {
		parts = append(parts, fmt.Sprintf("%s %.0f%%", c.Name, c.Share*100))
	}
	return fmt.Sprintf("%s in %s (%d observations): %s",
		kind, src, m.Observations, strings.Join(parts, ", "))
}
