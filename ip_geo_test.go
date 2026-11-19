package main

import "testing"

func TestCountryName(t *testing.T) {
	cases := map[string]string{
		"US": "United States",
		"us": "United States",
		"CN": "China",
		"GB": "United Kingdom",
		"HK": "Hong Kong",
		"TW": "Taiwan",
		"ZZ": "",
		"":   "",
	}
	for code, want := range cases {
		if got := countryName(code); got != want {
			t.Errorf("countryName(%q) = %q, want %q", code, got, want)
		}
	}
}

func TestGeoDataToIPInfo_CarriesAnycast(t *testing.T) {
	yes := true
	info := geoDataToIPInfo("8.8.8.8", &geoData{
		IP: "8.8.8.8", Country: "United States", CountryCode: "US",
		Anycast: &yes, Source: "ipinfo",
	}, "datacenter")
	if info.Anycast == nil || !*info.Anycast {
		t.Fatalf("anycast not copied: %+v", info.Anycast)
	}
	if info.GeoSource != "ipinfo" {
		t.Fatalf("geo_source = %q", info.GeoSource)
	}
}

func TestInfoHasLookupData(t *testing.T) {
	if infoHasLookupData(&IPInfo{IP: "1.2.3.4", ConnectionType: "unknown", GeoSource: "local"}) {
		t.Fatal("a local baseline must not count as provider data")
	}
	if !infoHasLookupData(&IPInfo{CountryCode: "US"}) {
		t.Fatal("a country code must count as provider data")
	}
	no := false
	if !infoHasLookupData(&IPInfo{Anycast: &no}) {
		t.Fatal("an explicit anycast=false still counts as provider data")
	}
}
