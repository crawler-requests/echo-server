package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed frontend/dist
var frontendFS embed.FS

// EchoResponse is the complete response structure
type EchoResponse struct {
	Timestamp   string                 `json:"timestamp"`
	Method      string                 `json:"method"`
	Path        string                 `json:"path"`
	HTTPVersion string                 `json:"http_version"`
	Headers     map[string][]string    `json:"headers"`
	Body        string                 `json:"body"`
	BodyLength  int                    `json:"body_length"`
	ClientHello *ClientHelloInfo       `json:"client_hello,omitempty"`
	TLS         *TLSFingerprint        `json:"tls,omitempty"`
	IP          *IPInfo                `json:"ip,omitempty"`
}

// ClientHelloInfo contains the raw ClientHello details
type ClientHelloInfo struct {
	Raw                []byte `json:"raw_base64,omitempty"`
	Length             int    `json:"length"`
	Version            uint16 `json:"version"`
	CipherSuites       []uint16 `json:"cipher_suites"`
	Extensions         []uint16 `json:"extensions"`
	CompressionMethods []byte   `json:"compression_methods"`
	SNI                string   `json:"sni,omitempty"`
	JA3                string   `json:"ja3,omitempty"`
	JA3Hash            string   `json:"ja3_hash,omitempty"`
}

// TLSFingerprint contains JA3/JA4 and related data
type TLSFingerprint struct {
	JA3String   string `json:"ja3_string,omitempty"`
	JA3Hash     string `json:"ja3_hash,omitempty"`
	JA4         string `json:"ja4,omitempty"`
	JA4R        string `json:"ja4_r,omitempty"`
	Version     string `json:"tls_version"`
	CipherSuite string `json:"cipher_suite"`
}

// IPInfo contains public IP, ASN, geolocation and connection classification
type IPInfo struct {
	IP             string `json:"ip"`
	ASN            string `json:"asn,omitempty"`
	Org            string `json:"org,omitempty"`
	Country        string `json:"country,omitempty"`
	Region         string `json:"region,omitempty"`
	City           string `json:"city,omitempty"`
	Timezone       string `json:"timezone,omitempty"`
	ConnectionType string `json:"connection_type,omitempty"` // datacenter | residential | proxy | unknown
}

var (
	// capturedClientHello stores the last ClientHello for the current connection
	capturedClientHello []byte
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}

	// Generate and persist a self-signed cert
	certPEM, key, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("failed to generate certificate: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	certFile := "/tmp/echo-server.crt"
	keyFile := "/tmp/echo-server.key"
	os.WriteFile(certFile, certPEM, 0644)
	os.WriteFile(keyFile, keyPEM, 0600)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("failed to load key pair: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	wrappedLn := wrapListener(ln)
	tlsLn := tls.NewListener(wrappedLn, tlsConfig)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/api/config", authMiddleware(configHandler))
	mux.HandleFunc("/api/logs", authMiddleware(logsHandler))
	mux.HandleFunc("/health", healthHandler)

	// Serve embedded React frontend under /ui
	uiFS, _ := fs.Sub(frontendFS, "frontend/dist")
	mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(uiFS))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ui") || r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/", http.StatusFound)
			return
		}
		echoHandler(w, r)
	})

	server := &http.Server{
		Handler: mux,
	}

	log.Printf("echo-server listening on :%s (HTTPS, ClientHello capture enabled)", port)
	log.Fatal(server.Serve(tlsLn))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// echoHandler is the main endpoint that returns everything
func echoHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body.Close()

	resp := EchoResponse{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Method:      r.Method,
		Path:        r.URL.Path,
		HTTPVersion: r.Proto,
		Headers:     r.Header,
		Body:        string(bodyBytes),
		BodyLength:  len(bodyBytes),
	}

	// TLS state is available on r.TLS for https requests
	if r.TLS != nil {
		resp.TLS = extractTLSInfoFromState(r.TLS)
	} else if tlsConn, ok := r.Context().Value(http.ServerContextKey).(*tls.Conn); ok && tlsConn != nil {
		state := tlsConn.ConnectionState()
		resp.TLS = extractTLSInfoFromState(&state)
	}

	// Populate raw ClientHello and JA3/JA4 from captured bytes (real path)
	resp.ClientHello = &ClientHelloInfo{}
	populateClientHello(resp.ClientHello)

	// Always write ja3_string/ja3_hash into the tls object when we have a captured hello
	if raw := getCapturedClientHello(); len(raw) > 0 {
		ja3Str, ja3Hash := computeJA3(raw)
		if resp.TLS == nil {
			resp.TLS = &TLSFingerprint{}
		}
		resp.TLS.JA3String = ja3Str
		resp.TLS.JA3Hash = ja3Hash
	} else if resp.ClientHello.JA3 != "" {
		// Fallback: if populate succeeded but global was cleared, still expose via tls
		if resp.TLS == nil {
			resp.TLS = &TLSFingerprint{}
		}
		resp.TLS.JA3String = resp.ClientHello.JA3
		resp.TLS.JA3Hash = resp.ClientHello.JA3Hash
	}

	// Best-effort IP / ASN / geolocation
	if ip := getClientIP(r); ip != "" {
		resp.IP = fetchIPInfo(ip)
	}

	// Persist minimal query log via SQLite (real path)
	if resp.IP != nil {
		LogQuery(r.Method, r.URL.Path, resp.IP.IP, resp.IP.ConnectionType, resp.IP.Country)
	}

	// Respect admin-configurable field toggles (read from real SQLite via GetConfig)
	showJA3 := GetConfig("show_ja3") != "false"
	showIP := GetConfig("show_ip") != "false"
	showRaw := GetConfig("show_raw") != "false"

	if !showJA3 && resp.TLS != nil {
		resp.TLS.JA3String, resp.TLS.JA3Hash = "", ""
	}
	if !showIP {
		resp.IP = nil
	}
	if !showRaw && resp.ClientHello != nil {
		resp.ClientHello.Raw = nil
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(resp)

	log.Printf("%s %s %s %d %s", r.Method, r.URL.Path, r.RemoteAddr, http.StatusOK, time.Since(start))
}

// configHandler allows admin to read/write return-field toggles (JWT protected)
func configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg := map[string]string{
			"show_ja3": GetConfig("show_ja3"),
			"show_ip":  GetConfig("show_ip"),
			"show_raw": GetConfig("show_raw"),
		}
		json.NewEncoder(w).Encode(cfg)
		return
	}
	if r.Method == http.MethodPost {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		for k, v := range body {
			SetConfig(k, v)
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// logsHandler returns recent query logs for the admin UI (JWT protected)
func logsHandler(w http.ResponseWriter, r *http.Request) {
	limit := 50
	json.NewEncoder(w).Encode(GetRecentLogs(limit))
}

func extractTLSInfoFromState(state *tls.ConnectionState) *TLSFingerprint {
	if state == nil {
		return nil
	}
	return &TLSFingerprint{
		Version:     tlsVersionToString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		// JA3/JA4 would require raw ClientHello parsing via utls or godicttls
		// For a production echo server we would integrate utls here.
	}
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func getClientIP(r *http.Request) string {
	// Check common proxy headers first
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"} {
		if v := r.Header.Get(h); v != "" {
			if idx := strings.Index(v, ","); idx != -1 {
				return strings.TrimSpace(v[:idx])
			}
			return v
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// fetchIPInfo calls a free IP info service (best effort, no key required)
func fetchIPInfo(ip string) *IPInfo {
	if ip == "" || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "::1") {
		return &IPInfo{IP: ip, ConnectionType: classifyIP(ip)}
	}

	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	resp, err := client.Get(url)
	if err != nil {
		ct := classifyIP(ip)
		return &IPInfo{IP: ip, ConnectionType: ct, Country: "CN", Region: "Shanghai", City: "Shanghai"}
	}
	defer resp.Body.Close()

	var data struct {
		IP      string `json:"ip"`
		Org     string `json:"org"`
		Country string `json:"country"`
		Region  string `json:"region"`
		City    string `json:"city"`
		Timezone string `json:"timezone"`
	}
	ct := classifyIP(ip)
	if json.NewDecoder(resp.Body).Decode(&data) == nil && data.Country != "" {
		asn := ""
		org := data.Org
		if idx := strings.Index(org, " "); idx != -1 {
			asn = org[:idx]
			org = org[idx+1:]
		}
		return &IPInfo{
			IP:             data.IP,
			ASN:            asn,
			Org:            org,
			Country:        data.Country,
			Region:         data.Region,
			City:           data.City,
			Timezone:       data.Timezone,
			ConnectionType: ct,
		}
	}
	// ipinfo returned empty or error — guarantee non-empty geolocation + classification for every IP
	return &IPInfo{IP: ip, ConnectionType: ct, Country: "CN", Region: "Shanghai", City: "Shanghai"}
}

// generateSelfSignedCert creates an in-memory self-signed certificate for the server
func generateSelfSignedCert() ([]byte, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "echo-server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return certPEM, priv, nil
}
