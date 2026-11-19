package ipclass

import "testing"

func TestOrgLooksDatacenter(t *testing.T) {
	positive := []string{
		"Amazon.com, Inc.",
		"Amazon Data Services",
		"Microsoft Corporation",
		"Google LLC",
		"DigitalOcean, LLC",
		"Hetzner Online GmbH",
		"OVH SAS",
		"Cloudflare, Inc.",
		"Vultr Holdings",
		"Alibaba (US) Technology Co., Ltd.",
	}
	for _, org := range positive {
		if !OrgLooksDatacenter(org) {
			t.Errorf("OrgLooksDatacenter(%q) = false, want true", org)
		}
	}

	negative := []string{
		"",
		"China Telecom",
		"Comcast Cable Communications, LLC",
		"Enecom, Inc.",
		"Verizon Business",
		"Charter Communications",
		// A street address is not a hosting brand: ipwho.is returns the ISP's
		// postal address as `org` for many mobile carriers.
		"234, Galle Road, Colombo 4",
		"Hutchison Telecommunications Lanka Private Limited",
	}
	for _, org := range negative {
		if OrgLooksDatacenter(org) {
			t.Errorf("OrgLooksDatacenter(%q) = true, want false", org)
		}
	}
}

// The embedded table was expanded with AWS/GCP/DigitalOcean official ranges;
// these representatives must classify as datacenter from the shipped table.
func TestExpandedDatacenterRanges(t *testing.T) {
	cases := []string{
		"52.1.2.3",    // AWS us-east-1
		"35.185.1.1",  // GCP
		"104.131.0.1", // DigitalOcean
		"13.32.0.1",   // CloudFront (AWS)
		"172.64.0.1",  // Cloudflare
		"23.8.8.8",    // Akamai edge
		"2.16.1.1",    // Akamai edge
	}
	for _, ip := range cases {
		if got := Classify(ip); got != "datacenter" {
			t.Errorf("Classify(%q) = %q, want datacenter", ip, got)
		}
	}
}

// A single overbroad /8 previously classified every address in 23.0.0.0/8 as
// datacenter, including AT&T/Comcast/Charter consumer lines. The table now uses
// Akamai's actually-announced prefixes instead; eyeball ISPs must stay unknown.
func TestConsumerIspsAreNotDatacenter(t *testing.T) {
	cases := []string{
		"23.115.64.123",  // AT&T
		"23.71.52.174",   // Comcast
		"23.87.125.42",   // Charter
		"23.232.186.42",  // NTT PC Communications
		"23.229.142.208", // GoDaddy (hosting-adjacent but consumer-facing reseller)
	}
	for _, ip := range cases {
		if got := Classify(ip); got == "datacenter" {
			t.Errorf("Classify(%q) = datacenter, want unknown (consumer ISP)", ip)
		}
	}
}
