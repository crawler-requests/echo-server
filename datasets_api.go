package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/crawler-requests/echo-server/datasets"
)

// Generic data-provider API. Every data set in the process (JA4 libraries,
// CIDR tables, keyword lists, …) is managed through the same endpoints, so a
// new dataset added in Go automatically appears in the admin UI without any
// handler changes.
//
//	GET    /api/datasets                       list datasets + providers + status
//	POST   /api/datasets?dataset=NAME          create/update a provider
//	DELETE /api/datasets?dataset=NAME&provider=P
//	POST   /api/datasets/sync?dataset=NAME[&provider=P]
//
// The pre-engine /api/ja4providers endpoints remain as aliases for the "ja4"
// dataset so existing scripts keep working.

// datasetCacheDir returns where remote/command payloads are cached. Override
// with ECHO_SERVER_DATASET_CACHE_DIR (default ~/.echo-server/datasets).
func datasetCacheDir() string {
	if d := os.Getenv("ECHO_SERVER_DATASET_CACHE_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("ECHO_SERVER_JA4_CACHE_DIR"); d != "" { // legacy
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "echo-server-datasets")
	}
	return filepath.Join(home, ".echo-server", "datasets")
}

// datasetProvidersKey is the SQLite config key holding one dataset's provider
// list.
func datasetProvidersKey(name string) string { return "dataset_providers:" + name }

// saveDatasetProviders persists one dataset's provider list.
func saveDatasetProviders(name string, cfgs []datasets.ProviderConfig) error {
	raw, err := json.Marshal(cfgs)
	if err != nil {
		return err
	}
	return SetConfig(datasetProvidersKey(name), string(raw))
}

// envDatasetConfig returns the environment-provided provider list for a
// dataset. DATASET_PROVIDERS holds a JSON object keyed by dataset name;
// JA4_PROVIDERS is the legacy single-dataset form.
func envDatasetConfig(name string) string {
	if raw := os.Getenv("DATASET_PROVIDERS"); raw != "" {
		var byDataset map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &byDataset); err == nil {
			if part, ok := byDataset[name]; ok {
				return string(part)
			}
		}
	}
	if name == "ja4" {
		return os.Getenv("JA4_PROVIDERS")
	}
	return ""
}

// initAllDatasets creates the data sets, attaches embedded defaults, loads
// persisted/环境 providers and starts background refresh loops. Called once
// from main before serving.
func initAllDatasets() {
	initJA4Dataset()
	initCIDRDatasets()
	initOrgDataset()
	for _, d := range datasets.All() {
		if m, ok := d.(interface{ Init() }); ok {
			m.Init()
		}
	}
}

// datasetJSON is one dataset's API representation.
type datasetJSON struct {
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Providers   []datasets.ProviderStatus `json:"providers"`
}

// datasetsHandler serves the generic provider API.
func datasetsHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("dataset")
	switch r.Method {
	case http.MethodGet:
		if name != "" {
			d, ok := datasets.Get(name)
			if !ok {
				http.Error(w, "unknown dataset: "+name, http.StatusBadRequest)
				return
			}
			writeJSON(w, datasetJSON{
				Name:        d.Name(),
				Description: d.Description(),
				Providers:   d.ListStatuses(),
			})
			return
		}
		out := make([]datasetJSON, 0, len(datasets.All()))
		for _, d := range datasets.All() {
			out = append(out, datasetJSON{
				Name:        d.Name(),
				Description: d.Description(),
				Providers:   d.ListStatuses(),
			})
		}
		writeJSON(w, out)
		return
	}

	d, ok := datasets.Get(name)
	if !ok {
		http.Error(w, "unknown dataset: "+name, http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPost:
		var req providerRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		st, err := d.Upsert(req.toConfig())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, st)
	case http.MethodDelete:
		if err := d.Delete(r.URL.Query().Get("provider")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// providerRequest is the POST body for a provider (pointer fields distinguish
// "omitted" from an explicit false/0).
type providerRequest struct {
	Name       string            `json:"name"`
	Kind       datasets.Kind     `json:"kind"`
	Enabled    *bool             `json:"enabled"`
	Priority   *int              `json:"priority"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Path       string            `json:"path"`
	Command    string            `json:"command"`
	Format     string            `json:"format"`
	RefreshMin *int              `json:"refresh_min"`
}

func (r providerRequest) toConfig() datasets.ProviderConfig {
	cfg := datasets.ProviderConfig{
		Name: r.Name, Kind: r.Kind, URL: r.URL, Headers: r.Headers, Path: r.Path,
		Command: r.Command, Format: r.Format,
		Enabled: true, Priority: 10,
	}
	if r.Enabled != nil {
		cfg.Enabled = *r.Enabled
	}
	if r.Priority != nil {
		cfg.Priority = *r.Priority
	}
	if r.RefreshMin != nil {
		cfg.RefreshMin = *r.RefreshMin
	}
	return cfg
}

// datasetsSyncHandler triggers an immediate refresh (all providers of one
// dataset, or a single provider). Sync runs in the background; poll the list
// to observe completion.
func datasetsSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	d, ok := datasets.Get(r.URL.Query().Get("dataset"))
	if !ok {
		http.Error(w, "unknown dataset", http.StatusBadRequest)
		return
	}
	if name := r.URL.Query().Get("provider"); name != "" {
		if err := checkSyncable(d, name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		go func() { _ = d.Sync(name) }()
	} else {
		go d.SyncAll(true)
	}
	writeJSON(w, map[string]string{"status": "syncing"})
}

// checkSyncable rejects a sync target that does not exist or cannot refresh,
// instead of returning "syncing" for a request that can never do anything.
func checkSyncable(d datasets.Dataset, name string) error {
	for _, s := range d.ListStatuses() {
		if s.Name != name {
			continue
		}
		if s.Kind == datasets.KindEmbedded {
			return errors.New("the builtin provider cannot be synced")
		}
		return nil
	}
	return errors.New("no such provider: " + name)
}

// ---------------------------------------------------------------------------
// Legacy aliases (pre-engine API), pinned to the "ja4" dataset.

func ja4providersHandler(w http.ResponseWriter, r *http.Request) {
	d, ok := datasets.Get("ja4")
	if !ok {
		http.Error(w, "ja4 dataset unavailable", http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, d.ListStatuses())
	case http.MethodPost:
		var req providerRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		st, err := d.Upsert(req.toConfig())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, st)
	case http.MethodDelete:
		if err := d.Delete(r.URL.Query().Get("name")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func ja4providersSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	d, ok := datasets.Get("ja4")
	if !ok {
		http.Error(w, "ja4 dataset unavailable", http.StatusInternalServerError)
		return
	}
	if name := r.URL.Query().Get("name"); name != "" {
		go func() { _ = d.Sync(name) }()
	} else {
		go d.SyncAll(true)
	}
	writeJSON(w, map[string]string{"status": "syncing"})
}
