package main

import (
	"net/http"
	"sort"
	"strings"
)

type ja4Hit struct {
	JA4          string            `json:"ja4"`
	Provider     string            `json:"provider"`
	Name         string            `json:"name,omitempty"`
	Family       string            `json:"family,omitempty"`
	Version      string            `json:"version,omitempty"`
	Confidence   float64           `json:"confidence"`
	Observations uint64            `json:"observations"`
	Verified     bool              `json:"verified"`
	Clients      []ClientCandidate `json:"clients"`
}

// ja4SearchHandler searches every configured JA4 library by fingerprint
// prefix or by client name/family. Without ?q= it returns the highest-evidence
// fingerprints, which doubles as a "most common clients" view.
func ja4SearchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := 40
	if v := r.URL.Query().Get("limit"); v != "" {
		if n := atoiSafe(v); n > 0 {
			limit = min(n, 200)
		}
	}
	type scored struct {
		score int
		hit   ja4Hit
	}
	var all []scored
	appendLib := func(libName string, exact map[string]*dbAgg) {
		for fp, agg := range exact {
			if agg == nil {
				continue
			}
			score := 1
			if q == "" {
				score = 1
			} else if strings.Contains(strings.ToLower(fp), q) {
				score = 2
			} else {
				matched := false
				for _, v := range agg.votes {
					if strings.Contains(strings.ToLower(v.name), q) ||
						strings.Contains(strings.ToLower(v.family), q) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}
			m := aggToMatch(agg, true)
			if m == nil {
				continue
			}
			all = append(all, scored{score: score, hit: ja4Hit{
				JA4: fp, Provider: libName, Name: m.Name, Family: m.Family,
				Version: m.Version, Confidence: m.Confidence, Observations: m.Observations,
				Verified: m.Verified, Clients: m.Candidates,
			}})
		}
	}
	if ja4Mgr != nil {
		if set := ja4Mgr.Current(); set != nil {
			for _, lib := range set.libs {
				appendLib(lib.name, lib.exact)
			}
		}
	} else if ja4DB.ok {
		appendLib("builtin", ja4DB.exact)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].score != all[j].score {
			return all[i].score > all[j].score
		}
		return all[i].hit.Observations > all[j].hit.Observations
	})
	if len(all) > limit {
		all = all[:limit]
	}
	out := make([]ja4Hit, 0, len(all))
	for _, s := range all {
		out = append(out, s.hit)
	}
	writeJSON(w, map[string]any{"query": q, "count": len(out), "items": out})
}

// ja4StatsHandler summarises the loaded fingerprint libraries.
func ja4StatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	type providerStat struct {
		Name         string `json:"name"`
		Entries      int    `json:"entries"`
		Observations uint64 `json:"observations"`
		Source       string `json:"source,omitempty"`
		Exported     string `json:"exported,omitempty"`
		Generated    string `json:"generated,omitempty"`
	}
	var providers []providerStat
	totalEntries := 0
	var totalObs uint64
	add := func(name string, lib *ja4Lib) {
		if lib == nil {
			return
		}
		ps := providerStat{
			Name: name, Entries: len(lib.exact), Observations: lib.totalObs,
			Source: lib.meta.Source, Exported: lib.meta.Exported, Generated: lib.meta.Generated,
		}
		providers = append(providers, ps)
		totalEntries += ps.Entries
		totalObs += ps.Observations
	}
	if ja4Mgr != nil {
		if set := ja4Mgr.Current(); set != nil {
			for _, lib := range set.libs {
				add(lib.name, lib)
			}
		}
	}
	if len(providers) == 0 && ja4DB.ok {
		add("builtin", &ja4Lib{name: "builtin", meta: ja4DB.meta, exact: ja4DB.exact, totalObs: 0})
		for _, a := range ja4DB.exact {
			if a != nil {
				providers[len(providers)-1].Observations += a.obs
			}
		}
		totalObs = providers[len(providers)-1].Observations
	}
	writeJSON(w, map[string]any{
		"providers":          providers,
		"total_entries":      totalEntries,
		"total_observations": totalObs,
	})
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return 0
		}
	}
	return n
}
