package main

import (
	"errors"
	"strings"

	"github.com/crawler-requests/echo-server/datasets"
)

// The "ja4" dataset: TLS fingerprint libraries. Values are compiled ja4Lib
// objects; the runtime value keeps them in provider priority order so the
// first library that knows a fingerprint decides, and the embedded snapshot
// is always the final fallback.

// ja4Codec decodes a library payload — the compacted JSON contract written by
// tools/ja4dbgen, or a community ja4_fingerprint.csv — into a ja4Lib.
type ja4Codec struct{}

func (ja4Codec) Decode(data []byte, format string) (*ja4Lib, error) {
	f, err := parseJA4Doc(data, format)
	if err != nil {
		return nil, err
	}
	lib := buildLib("", f)
	if lib == nil {
		return nil, errors.New("library contains no usable JA4 fingerprints")
	}
	return lib, nil
}

func (ja4Codec) Stats(l *ja4Lib) datasets.Stats {
	return datasets.Stats{
		Entries:      len(l.exact),
		Observations: l.totalObs,
		Source:       l.meta.Source,
		Exported:     l.meta.Exported,
	}
}

// Merge keeps provider order: exact/prefix lookup walks the list in order.
func (ja4Codec) Merge(parts []*ja4Lib) *ja4LibSet {
	return &ja4LibSet{libs: parts}
}

// parseJA4Doc decides between the JSON contract and a community CSV. The
// format hint wins; otherwise a leading "{" means JSON.
func parseJA4Doc(data []byte, format string) (*dbFile, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "csv":
		return parseJA4CSV(data)
	case "json":
		return parseLibraryJSON(data)
	}
	trimmed := strings.TrimLeft(string(data), " \t\r\n")
	if strings.HasPrefix(trimmed, "{") {
		return parseLibraryJSON(data)
	}
	return parseJA4CSV(data)
}

// ja4Mgr assembles the "ja4" dataset from its providers.
var ja4Mgr *datasets.Manager[*ja4Lib, *ja4LibSet]

func initJA4Dataset() {
	ja4Mgr = datasets.New[*ja4Lib, *ja4LibSet]("ja4", ja4Codec{}, datasets.Options[*ja4Lib, *ja4LibSet]{
		Description: "JA4 TLS 指纹库：把 ClientHello 指纹映射到真实的客户端",
		CacheDir:    datasetCacheDir(),
		Saver: func(cfgs []datasets.ProviderConfig) error {
			return saveDatasetProviders("ja4", cfgs)
		},
		LoadConfig: func() (string, string) {
			persisted := GetConfig(datasetProvidersKey("ja4"))
			if persisted == "" {
				// Backward compatibility with the pre-engine key.
				persisted = GetConfig("ja4_providers")
			}
			return persisted, envDatasetConfig("ja4")
		},
		Stamp: func(l *ja4Lib, provider string) *ja4Lib {
			l.name = provider // attribution: source becomes "ja4db:<provider>"
			return l
		},
	})
	if embeddedJA4Lib != nil {
		ja4Mgr.SetEmbedded(embeddedJA4Lib)
	}
}
