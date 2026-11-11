package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crawler-requests/echo-server/datasets"
	"github.com/crawler-requests/echo-server/ipclass"
)

// resetDatasets rebuilds every dataset (embedded default + no custom
// providers) and restores the ipclass runtime tables on cleanup, so changes
// made by provider tests never leak into other tests.
func resetDatasets(t *testing.T) {
	t.Helper()
	datasets.ResetRegistryForTest()
	initJA4Dataset()
	initCIDRDatasets()
	initOrgDataset()
	t.Cleanup(func() {
		ipclass.SetDatacenterRanges(nil)
		ipclass.SetResidentialRanges(nil)
		ipclass.SetDatacenterOrgKeywords(nil)
	})
}

// writeCIDRFile writes a CIDR payload with one prefix per line.
func writeCIDRFile(t *testing.T, cidrs ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ranges.txt")
	if err := os.WriteFile(path, []byte(strings.Join(cidrs, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A CIDR table from a file provider must drive classification: adding a range
// turns the covered IPs into datacenter, removing it restores "unknown".
// 203.0.113.0/24 is the TEST-NET-3 documentation range and is not in any
// embedded table.
func TestDatacenterCIDR_FileProvider_DrivesClassification(t *testing.T) {
	resetDatasets(t)
	const ip = "203.0.113.5"
	if got := ipclass.Classify(ip); got != "unknown" {
		t.Fatalf("before: Classify(%s) = %q, want unknown", ip, got)
	}

	path := writeCIDRFile(t, "203.0.113.0/24")
	st, err := dcRangeMgr.Upsert(datasets.ProviderConfig{
		Name: "docnet", Kind: datasets.KindFile, Enabled: true, Priority: 10, Path: path,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if st.Status != "ok" || st.Entries != 1 {
		t.Fatalf("status = %+v", st)
	}
	if got := ipclass.Classify(ip); got != "datacenter" {
		t.Fatalf("after: Classify(%s) = %q, want datacenter", ip, got)
	}
	// The effective runtime table is a union: it contains the custom range on
	// top of the embedded defaults.
	if len(ipclass.DatacenterRanges()) <= len(ipclass.DefaultDatacenterRanges()) {
		t.Fatal("runtime table should be a superset of the embedded table")
	}

	if err := dcRangeMgr.Delete("docnet"); err != nil {
		t.Fatal(err)
	}
	if got := ipclass.Classify(ip); got != "unknown" {
		t.Fatalf("after delete: Classify(%s) = %q, want unknown", ip, got)
	}
}

// Same for residential-proxy exits: a custom table flips classification.
func TestResidentialCIDR_FileProvider_DrivesClassification(t *testing.T) {
	resetDatasets(t)
	const ip = "203.0.113.9"
	path := writeCIDRFile(t, "203.0.113.0/24")
	if _, err := rpRangeMgr.Upsert(datasets.ProviderConfig{
		Name: "exit", Kind: datasets.KindFile, Enabled: true, Priority: 10, Path: path,
	}); err != nil {
		t.Fatal(err)
	}
	if got := ipclass.Classify(ip); got != "residential_proxy" {
		t.Fatalf("Classify(%s) = %q, want residential_proxy", ip, got)
	}
}

// A keyword list from a file provider extends the org-name heuristic.
func TestOrgKeywords_FileProvider_ExtendsHeuristic(t *testing.T) {
	resetDatasets(t)
	if ipclass.OrgLooksDatacenter("AcmeCloud LTD") {
		t.Fatal("baseline: AcmeCloud should not look like a datacenter")
	}
	path := filepath.Join(t.TempDir(), "kw.txt")
	if err := os.WriteFile(path, []byte("# hosting brands\nacmecloud\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := orgKeywordMgr.Upsert(datasets.ProviderConfig{
		Name: "extra", Kind: datasets.KindFile, Enabled: true, Priority: 10, Path: path,
	}); err != nil {
		t.Fatal(err)
	}
	if !ipclass.OrgLooksDatacenter("AcmeCloud LTD") {
		t.Fatal("after: AcmeCloud should look like a datacenter via the custom keyword")
	}
}

// A command provider generates data at runtime: any executable the operator
// has can feed a dataset without writing Go.
func TestDatacenterCIDR_CommandProvider(t *testing.T) {
	resetDatasets(t)
	const ip = "203.0.113.77"
	st, err := dcRangeMgr.Upsert(datasets.ProviderConfig{
		Name: "generator", Kind: datasets.KindCommand, Enabled: true, Priority: 10,
		Command: "printf '203.0.113.0/24\\n'",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if st.Status != "ok" {
		t.Fatalf("status = %+v", st)
	}
	if got := ipclass.Classify(ip); got != "datacenter" {
		t.Fatalf("Classify(%s) = %q, want datacenter from command provider", ip, got)
	}
	if st.LastSync == "" {
		t.Fatal("command provider missing last_sync")
	}

	// A failing command reports an error but keeps the last good value.
	failSt, err := dcRangeMgr.Upsert(datasets.ProviderConfig{
		Name: "generator", Kind: datasets.KindCommand, Enabled: true, Priority: 10,
		Command: "exit 2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if failSt.Status != "error" {
		t.Fatalf("status = %+v, want error", failSt)
	}
	if got := ipclass.Classify(ip); got != "datacenter" {
		t.Fatalf("classification lost after failed command: %q", got)
	}
}

// The generic admin API: GET lists every dataset, POST upserts a provider for
// a named dataset, DELETE removes it. Handlers are tested directly (auth is a
// route-level concern tested elsewhere).
func TestDatasetsAPI_ListUpsertDelete(t *testing.T) {
	resetDatasets(t)

	// GET /api/datasets → all four datasets with their builtin provider.
	req := httptest.NewRequest(http.MethodGet, "/api/datasets", nil)
	rec := httptest.NewRecorder()
	datasetsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d", rec.Code)
	}
	var list []datasetJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 4 {
		t.Fatalf("datasets = %d, want 4: %+v", len(list), list)
	}
	seen := map[string]bool{}
	for _, d := range list {
		if seen[d.Name] {
			t.Fatalf("duplicate dataset %q", d.Name)
		}
		seen[d.Name] = true
		if len(d.Providers) == 0 || d.Providers[0].Name != "builtin" {
			t.Fatalf("dataset %s: providers = %+v, want builtin present", d.Name, d.Providers)
		}
	}
	for _, want := range []string{"ja4", "datacenter_cidr", "residential_proxy_cidr", "datacenter_orgs"} {
		if !seen[want] {
			t.Fatalf("dataset %q missing from %v", want, list)
		}
	}

	// POST /api/datasets?dataset=datacenter_cidr upserts a provider.
	path := writeCIDRFile(t, "203.0.113.0/24")
	body, _ := json.Marshal(map[string]any{
		"name": "api-add", "kind": "file", "path": path, "priority": 5,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/datasets?dataset=datacenter_cidr", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	datasetsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST status = %d body=%s", rec.Code, rec.Body.String())
	}
	var st datasets.ProviderStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Status != "ok" || st.Name != "api-add" {
		t.Fatalf("upserted = %+v", st)
	}
	if got := ipclass.Classify("203.0.113.5"); got != "datacenter" {
		t.Fatalf("classification via API-added provider = %q", got)
	}

	// DELETE /api/datasets?dataset=datacenter_cidr&provider=api-add
	req = httptest.NewRequest(http.MethodDelete, "/api/datasets?dataset=datacenter_cidr&provider=api-add", nil)
	rec = httptest.NewRecorder()
	datasetsHandler(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d body=%s", rec.Code, rec.Body.String())
	}

	// Unknown dataset → 400.
	req = httptest.NewRequest(http.MethodPost, "/api/datasets?dataset=nope", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	datasetsHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown dataset status = %d", rec.Code)
	}
}

// The pre-engine /api/ja4providers endpoints remain aliases of the "ja4"
// dataset.
func TestDatasetsAPI_GetOneAndRemoteHeaders(t *testing.T) {
	resetDatasets(t)

	// ?dataset= returns that one dataset object (no array wrapper).
	req := httptest.NewRequest(http.MethodGet, "/api/datasets?dataset=ja4", nil)
	rec := httptest.NewRecorder()
	datasetsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET one status = %d body=%s", rec.Code, rec.Body.String())
	}
	var one datasetJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil {
		t.Fatalf("GET ?dataset= must return an object, got %s (%v)", rec.Body.String(), err)
	}
	if one.Name != "ja4" || len(one.Providers) == 0 {
		t.Fatalf("dataset = %+v", one)
	}

	// A remote provider's headers reach the server, and the API masks them.
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("198.51.100.0/24\n"))
	}))
	defer srv.Close()
	body, _ := json.Marshal(map[string]any{
		"name": "cloud", "kind": "remote", "priority": 20,
		"url": srv.URL, "refresh_min": 60,
		"headers": map[string]string{"Authorization": "Bearer t0k"},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/datasets?dataset=datacenter_cidr", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	datasetsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST remote status = %d body=%s", rec.Code, rec.Body.String())
	}
	var st datasets.ProviderStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer t0k" {
		t.Fatalf("upstream saw Authorization %q", gotAuth)
	}
	if st.Headers["Authorization"] != datasets.MaskedHeader {
		t.Fatalf("status leaked headers: %+v", st.Headers)
	}
	if got := ipclass.Classify("198.51.100.7"); got != "datacenter" {
		t.Fatalf("remote-provided CIDR did not drive classification: %q", got)
	}
}

func TestDatasetsSyncHandlerValidation(t *testing.T) {
	resetDatasets(t)
	for _, q := range []string{
		"?dataset=datacenter_cidr&provider=nope",
		"?dataset=datacenter_cidr&provider=builtin",
		"?dataset=nope",
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/datasets/sync"+q, nil)
		rec := httptest.NewRecorder()
		datasetsSyncHandler(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST /api/datasets/sync%s = %d, want 400 (%s)", q, rec.Code, rec.Body.String())
		}
	}
}

func TestJa4providersAlias(t *testing.T) {
	resetDatasets(t)
	req := httptest.NewRequest(http.MethodGet, "/api/ja4providers", nil)
	rec := httptest.NewRecorder()
	ja4providersHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/ja4providers = %d", rec.Code)
	}
	var list []datasets.ProviderStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "builtin" {
		t.Fatalf("ja4providers alias = %+v", list)
	}

	path := writeTempLibrary(t, "t13d9999zz_aaaaaaaaaaaa_bbbbbbbbbbbb", "curl/8.5.0", 5)
	body, _ := json.Marshal(map[string]any{
		"name": "alias", "kind": "file", "path": path,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/ja4providers", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	ja4providersHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/ja4providers = %d body=%s", rec.Code, rec.Body.String())
	}
	var st datasets.ProviderStatus
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Name != "alias" || st.Status != "ok" {
		t.Fatalf("aliased upsert = %+v", st)
	}

	// Sync endpoint accepts the alias.
	req = httptest.NewRequest(http.MethodPost, "/api/ja4providers/sync", nil)
	rec = httptest.NewRecorder()
	ja4providersSyncHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/ja4providers/sync = %d", rec.Code)
	}
}

// initAllDatasets wires everything together the way main() does.
func TestInitAllDatasets(t *testing.T) {
	resetDatasets(t)
	initAllDatasets()
	if len(datasets.All()) != 4 {
		t.Fatalf("datasets after initAllDatasets = %d, want 4", len(datasets.All()))
	}
	if got := ipclass.Classify("8.8.8.8"); got == "" {
		t.Fatal("classification should work after full init")
	}
}
