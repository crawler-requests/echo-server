package main

import (
	"errors"
	"net"
	"strings"

	"github.com/crawler-requests/echo-server/datasets"
	"github.com/crawler-requests/echo-server/ipclass"
)

// The IP-intelligence datasets: the datacenter prefix table, the
// residential-proxy prefix table, and the hosting-brand keyword list. Each is
// an ordinary dataset, so an operator can mount a fresher table from a local
// directory, pull one from a cloud URL, or generate one with a script. The
// compiled-in tables remain the builtin fallback provider.

// ---------------------------------------------------------------------------
// CIDR ranges

// cidrSet is a decoded CIDR table.
type cidrSet struct {
	nets []net.IPNet
}

// cidrCodec decodes the line-oriented CIDR format used by the embedded tables
// (also accepts a CSV column list; the first comma-separated field is the
// prefix).
type cidrCodec struct{}

func (cidrCodec) Decode(data []byte, format string) (*cidrSet, error) {
	nets := ipclass.ParseCIDRList(data)
	if len(nets) == 0 {
		return nil, errors.New("no CIDR prefixes found")
	}
	return &cidrSet{nets: nets}, nil
}

func (cidrCodec) Stats(v *cidrSet) datasets.Stats {
	return datasets.Stats{Entries: len(v.nets)}
}

// Merge unions every provider's prefixes; runtime tables are additive.
func (cidrCodec) Merge(parts []*cidrSet) *cidrSet {
	out := &cidrSet{}
	for _, p := range parts {
		out.nets = append(out.nets, p.nets...)
	}
	return out
}

var (
	dcRangeMgr *datasets.Manager[*cidrSet, *cidrSet]
	rpRangeMgr *datasets.Manager[*cidrSet, *cidrSet]
)

func initCIDRDatasets() {
	dcRangeMgr = datasets.New[*cidrSet, *cidrSet]("datacenter_cidr", cidrCodec{}, datasets.Options[*cidrSet, *cidrSet]{
		Description: "数据中心 / 云厂商 IP 段：命中即判定 datacenter",
		CacheDir:    datasetCacheDir(),
		Saver: func(cfgs []datasets.ProviderConfig) error {
			return saveDatasetProviders("datacenter_cidr", cfgs)
		},
		LoadConfig: func() (string, string) {
			return GetConfig(datasetProvidersKey("datacenter_cidr")), envDatasetConfig("datacenter_cidr")
		},
		OnChange: func(v *cidrSet) { ipclass.SetDatacenterRanges(v.nets) },
	})
	dcRangeMgr.SetEmbedded(&cidrSet{nets: ipclass.DefaultDatacenterRanges()})

	rpRangeMgr = datasets.New[*cidrSet, *cidrSet]("residential_proxy_cidr", cidrCodec{}, datasets.Options[*cidrSet, *cidrSet]{
		Description: "住宅代理出口 IP 段：命中即判定 residential_proxy",
		CacheDir:    datasetCacheDir(),
		Saver: func(cfgs []datasets.ProviderConfig) error {
			return saveDatasetProviders("residential_proxy_cidr", cfgs)
		},
		LoadConfig: func() (string, string) {
			return GetConfig(datasetProvidersKey("residential_proxy_cidr")), envDatasetConfig("residential_proxy_cidr")
		},
		OnChange: func(v *cidrSet) { ipclass.SetResidentialRanges(v.nets) },
	})
	rpRangeMgr.SetEmbedded(&cidrSet{nets: ipclass.DefaultResidentialRanges()})
}

// ---------------------------------------------------------------------------
// Hosting-brand keywords

// keywordSet is a decoded keyword list (lowercased at parse time).
type keywordSet struct {
	words []string
}

type keywordCodec struct{}

func (keywordCodec) Decode(data []byte, format string) (*keywordSet, error) {
	words := ipclass.ParseKeywordList(data)
	if len(words) == 0 {
		return nil, errors.New("no keywords found")
	}
	return &keywordSet{words: words}, nil
}

func (keywordCodec) Stats(v *keywordSet) datasets.Stats {
	return datasets.Stats{Entries: len(v.words)}
}

func (keywordCodec) Merge(parts []*keywordSet) *keywordSet {
	out := &keywordSet{}
	for _, p := range parts {
		out.words = append(out.words, p.words...)
	}
	return out
}

var orgKeywordMgr *datasets.Manager[*keywordSet, *keywordSet]

func initOrgDataset() {
	orgKeywordMgr = datasets.New[*keywordSet, *keywordSet]("datacenter_orgs", keywordCodec{}, datasets.Options[*keywordSet, *keywordSet]{
		Description: "机房 / 云厂商 ASN 组织名关键词：本地 CIDR 未命中时的兜底判定",
		CacheDir:    datasetCacheDir(),
		Saver: func(cfgs []datasets.ProviderConfig) error {
			return saveDatasetProviders("datacenter_orgs", cfgs)
		},
		LoadConfig: func() (string, string) {
			return GetConfig(datasetProvidersKey("datacenter_orgs")), envDatasetConfig("datacenter_orgs")
		},
		OnChange: func(v *keywordSet) { ipclass.SetDatacenterOrgKeywords(v.words) },
	})
	var words []string
	for _, w := range ipclass.DatacenterOrgKeywords() {
		words = append(words, strings.ToLower(w))
	}
	orgKeywordMgr.SetEmbedded(&keywordSet{words: words})
}
