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
	}
	for _, ip := range cases {
		if got := Classify(ip); got != "datacenter" {
			t.Errorf("Classify(%q) = %q, want datacenter", ip, got)
		}
	}
}
