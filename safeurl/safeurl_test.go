package safeurl

import (
	"net"
	"testing"
	"time"
)

func TestValidateURL_BlocksInternalTargets(t *testing.T) {
	blocked := []string{
		"http://127.0.0.1/x", "http://127.0.0.1:17777/x",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/x", "http://172.16.5.4/x", "http://192.168.1.1/x",
		"http://[::1]/x", "http://localhost/x", "http://foo.localhost/x",
		"http://0.0.0.0/x", "http://100.64.0.1/x",
	}
	for _, u := range blocked {
		if err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) allowed an internal target", u)
		}
	}
	allowed := []string{"https://api.example.com/x", "http://8.8.8.8/x", "https://ipwho.is/1.2.3.4"}
	for _, u := range allowed {
		if err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) rejected a public target: %v", u, err)
		}
	}
	bad := []string{"file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO", "ftp://x/y"}
	for _, u := range bad {
		if err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) allowed a non-http scheme", u)
		}
	}
}

func TestBlockedIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1",
		"169.254.169.254", "::1", "fe80::1", "fc00::1", "0.0.0.0", "224.0.0.1"} {
		if !BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = false, want true", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if BlockedIP(net.ParseIP(s)) {
			t.Errorf("BlockedIP(%s) = true, want false", s)
		}
	}
}

func TestSafeDialer_RefusesLoopback(t *testing.T) {
	dial := SafeDialer(time.Second)
	conn, err := dial(nil, "tcp", "127.0.0.1:9")
	if err == nil {
		conn.Close()
		t.Fatal("SafeDialer connected to loopback")
	}
}
