package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/base64"
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
	"path"
	"sort"
	"strings"
	"time"
)

//go:embed frontend/dist
var frontendFS embed.FS

// EchoResponse is the complete response structure
type EchoResponse struct {
	Timestamp   string              `json:"timestamp"`
	Method      string              `json:"method"`
	Scheme      string              `json:"scheme"`
	Host        string              `json:"host"`
	RemoteAddr  string              `json:"remote_addr"`
	Path        string              `json:"path"`
	Query       string              `json:"query,omitempty"`
	HTTPVersion string              `json:"http_version"`
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body"`
	BodyLength  int                 `json:"body_length"`
	ClientHello *ClientHelloInfo    `json:"client_hello,omitempty"`
	Client      *ClientInfo         `json:"client,omitempty"` // inferred client identification
	JA4H        string              `json:"ja4h,omitempty"`   // HTTP-layer client fingerprint
	TLS         *TLSFingerprint     `json:"tls,omitempty"`
	IP          *IPInfo             `json:"ip,omitempty"`
}

// ClientHelloInfo contains the raw ClientHello details
type ClientHelloInfo struct {
	Raw           string `json:"raw_base64,omitempty"`        // ClientHello message, base64 (encoded once)
	RawHex        string `json:"raw_hex,omitempty"`           // ClientHello message, hex
	RawRecord     string `json:"raw_record_base64,omitempty"` // TLS record(s) incl. 5-byte headers, base64
	Length        int    `json:"length"`                      // handshake message length (header included)
	RecordLength  int    `json:"record_length,omitempty"`     // total bytes of the carrying TLS records
	RecordCount   int    `json:"record_count,omitempty"`      // records the ClientHello spanned
	RecordVersion uint16 `json:"record_version,omitempty"`    // version field of the first record

	Version             uint16   `json:"version"` // legacy_version in the ClientHello
	CipherSuites        []uint16 `json:"cipher_suites"`
	Extensions          []uint16 `json:"extensions"`
	CompressionMethods  []byte   `json:"compression_methods"`
	SNI                 string   `json:"sni,omitempty"`
	ALPN                []string `json:"alpn,omitempty"`
	SupportedVersions   []uint16 `json:"supported_versions,omitempty"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms,omitempty"`
	SupportedGroups     []uint16 `json:"supported_groups,omitempty"`
	KeyShareGroups      []uint16 `json:"key_share_groups,omitempty"`
	HasGREASE           bool     `json:"has_grease,omitempty"`
	HasECH              bool     `json:"ech,omitempty"`

	JA3     string `json:"ja3,omitempty"`
	JA3Hash string `json:"ja3_hash,omitempty"`
	JA4     string `json:"ja4,omitempty"`
	JA4R    string `json:"ja4_r,omitempty"`
	JA4O    string `json:"ja4_o,omitempty"`
}

// TLSFingerprint contains JA3/JA4 and negotiated TLS data
type TLSFingerprint struct {
	JA3String   string `json:"ja3_string,omitempty"`
	JA3Hash     string `json:"ja3_hash,omitempty"`
	JA4         string `json:"ja4,omitempty"`
	JA4R        string `json:"ja4_r,omitempty"`
	JA4O        string `json:"ja4_o,omitempty"`
	Version     string `json:"tls_version"`
	CipherSuite string `json:"cipher_suite"`
	ServerName  string `json:"server_name,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	Resumed     bool   `json:"resumed,omitempty"`
}

// IPInfo contains public IP, ASN, geolocation and connection classification
type IPInfo struct {
	IP             string  `json:"ip"`
	ASN            string  `json:"asn,omitempty"`
	ASNName        string  `json:"asn_name,omitempty"`
	Org            string  `json:"org,omitempty"`
	ISP            string  `json:"isp,omitempty"`
	Country        string  `json:"country,omitempty"`
	CountryCode    string  `json:"country_code,omitempty"`
	Region         string  `json:"region,omitempty"`
	City           string  `json:"city,omitempty"`
	Postal         string  `json:"postal,omitempty"`
	Timezone       string  `json:"timezone,omitempty"`
	UTCOffset      string  `json:"utc_offset,omitempty"`
	Continent      string  `json:"continent,omitempty"`
	Latitude       float64 `json:"latitude,omitempty"`
	Longitude      float64 `json:"longitude,omitempty"`
	ConnectionType string  `json:"connection_type,omitempty"` // datacenter | residential_proxy | unknown
	IsProxy        *bool   `json:"is_proxy,omitempty"`
	IsVPN          *bool   `json:"is_vpn,omitempty"`
	IsTor          *bool   `json:"is_tor,omitempty"`
	IsHosting      *bool   `json:"is_hosting,omitempty"`
	GeoSource      string  `json:"geo_source,omitempty"` // ipwhois | ipapi | ipinfo | local
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
	// Public account entry points: first-run setup, login, and optional
	// self-registration (admin-controlled, new accounts are viewers).
	mux.HandleFunc("/api/setup/status", setupStatusHandler)
	mux.HandleFunc("/api/setup", setupHandler)
	mux.HandleFunc("/api/register", registerHandler)
	mux.HandleFunc("/api/login", loginHandler)
	// Account system: every authenticated user can read their own profile and
	// rotate their password; only admins can manage other accounts.
	mux.HandleFunc("/api/me", authMiddleware(meHandler))
	mux.HandleFunc("/api/me/password", authMiddleware(changePasswordHandler))
	mux.HandleFunc("/api/users", adminMiddleware(usersHandler))
	mux.HandleFunc("/api/config", adminWriteMiddleware(configHandler))
	mux.HandleFunc("/api/logs", authMiddleware(logsHandler))
	mux.HandleFunc("/api/stats", authMiddleware(statsHandler))
	// Data-provider API: every dataset (JA4 libs, CIDR tables, keywords, …)
	// is configured through the same endpoints.
	mux.HandleFunc("/api/datasets", adminWriteMiddleware(datasetsHandler))
	mux.HandleFunc("/api/datasets/sync", adminWriteMiddleware(datasetsSyncHandler))
	// IP-intelligence chain: built-in drivers (ipwho.is → ip-api.com → ipinfo.io)
	// plus operator-added cloud APIs / commands, in priority order.
	mux.HandleFunc("/api/ipproviders", adminWriteMiddleware(ipProvidersHandler))
	mux.HandleFunc("/api/ipproviders/test", adminWriteMiddleware(ipProvidersTestHandler))
	// Legacy JA4 endpoints remain as aliases for the "ja4" dataset.
	mux.HandleFunc("/api/ja4providers", adminWriteMiddleware(ja4providersHandler))
	mux.HandleFunc("/api/ja4providers/sync", adminWriteMiddleware(ja4providersSyncHandler))
	// Observability & operations: audit trail, notifications, metrics, exports,
	// scheduled maintenance and destructive admin actions.
	mux.HandleFunc("/api/audit", authMiddleware(auditHandler))
	mux.HandleFunc("/api/audit/export.csv", authMiddleware(auditHandler))
	mux.HandleFunc("/api/notifications", authMiddleware(notificationHandler))
	mux.HandleFunc("/api/views", authMiddleware(savedViewHandler))
	mux.HandleFunc("/api/apikeys", adminMiddleware(apiKeysHandler))
	mux.HandleFunc("/api/webhooks", adminMiddleware(webhookHandler))
	mux.HandleFunc("/api/webhooks/test", adminMiddleware(webhookTestHandler))
	mux.HandleFunc("/api/system", authMiddleware(systemHandler))
	mux.HandleFunc("/api/system/environment", adminMiddleware(environmentHandler))
	mux.HandleFunc("/api/system/backup", adminMiddleware(backupHandler))
	mux.HandleFunc("/api/system/purge-logs", adminMiddleware(purgeLogsHandler))
	mux.HandleFunc("/api/system/rotate-jwt", adminMiddleware(rotateJWTHandler))
	mux.HandleFunc("/api/metrics/summary", authMiddleware(metricsSummaryHandler))
	mux.HandleFunc("/metrics", prometheusHandler)
	mux.HandleFunc("/api/export/logs.csv", authMiddleware(logsExportHandler))
	mux.HandleFunc("/api/export/logs.json", authMiddleware(logsExportHandler))
	mux.HandleFunc("/api/export/users.csv", adminMiddleware(usersExportHandler))
	mux.HandleFunc("/api/export/users.json", adminMiddleware(usersExportHandler))
	mux.HandleFunc("/api/export/config.json", adminMiddleware(configExportHandler))
	mux.HandleFunc("/api/replay", adminMiddleware(replayHandler))
	mux.HandleFunc("/api/ja4/search", authMiddleware(ja4SearchHandler))
	mux.HandleFunc("/api/ja4/stats", authMiddleware(ja4StatsHandler))
	mux.HandleFunc("/api/openapi.json", openAPIHandler)
	mux.HandleFunc("/api/endpoints", authMiddleware(endpointsHandler))
	mux.HandleFunc("/health", healthHandler)

	// Serve embedded React frontend under /ui. Unknown extension-less paths
	// fall back to index.html so client-side routes survive a refresh
	// (e.g. /ui/users), while missing assets still return an honest 404.
	uiFS, _ := fs.Sub(frontendFS, "frontend/dist")
	mux.Handle("/ui/", http.StripPrefix("/ui/", newSPAHandler(uiFS)))

	// Root handler: SPA redirect for / and /ui*, echo handler otherwise.
	// When require_token=true, the echo endpoint enforces a valid JWT or API token.
	mux.HandleFunc("/", rootHandler)

	// Create the users table and, for headless deployments, bootstrap the first
	// admin from ECHO_SERVER_ADMIN_USERNAME/PASSWORD. Interactive installs stay
	// empty and get the first-admin setup wizard in the console.
	initUsers()
	// Assemble all data sets: embedded defaults attached, persisted/环境
	// providers loaded, remote auto-refresh loops started.
	initAllDatasets()
	// Assemble the IP-intelligence lookup chain (built-in drivers + custom
	// cloud APIs/commands). The legacy geo_* config keys keep working on top.
	initIPProviders()
	initExtraDB()
	startMaintenanceWorker()

	server := &http.Server{
		Handler: securityMiddleware(mux),
		// Bind each accepted connection into the request context so the
		// echo handler can read THIS connection's ClientHello (not a global,
		// which would cross-contaminate concurrent requests).
		// Serve() hands us the *tls.Conn; unwrap it to reach the helloConn
		// that captured the ClientHello before the handshake.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				if nc := tc.NetConn(); nc != nil {
					c = nc
				}
			}
			return context.WithValue(ctx, echoCtxKey{}, c)
		},
	}

	// A plain-HTTP listener makes the console reachable without accepting a
	// self-signed certificate warning. It serves the same routes (UI, APIs and
	// echo); only HTTPS carries TLS ClientHello/JA3/JA4 data. Set HTTP_PORT=0
	// to disable it.
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}
	if httpPort != "0" && !strings.EqualFold(httpPort, "off") {
		plainLn, err := net.Listen("tcp", ":"+httpPort)
		if err != nil {
			log.Printf("WARNING: plain HTTP listener on :%s failed: %v (console stays HTTPS-only)", httpPort, err)
		} else {
			plainServer := &http.Server{
				Handler: securityMiddleware(mux),
				ConnContext: func(ctx context.Context, c net.Conn) context.Context {
					return context.WithValue(ctx, echoCtxKey{}, c)
				},
			}
			go func() {
				log.Printf("console available over plain HTTP on :%s (http://<LAN-IP>:%s/ui/)", httpPort, httpPort)
				log.Fatal(plainServer.Serve(plainLn))
			}()
		}
	}

	log.Printf("echo-server listening on :%s (HTTPS, ClientHello capture enabled)", port)
	log.Fatal(server.Serve(tlsLn))
}

// rootHandler serves the SPA redirect and routes everything else to the echo
// endpoint, enforcing the optional token requirement.
func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/ui") {
		http.Redirect(w, r, "/ui/", http.StatusFound)
		return
	}
	if GetConfig("require_token") == "true" && !isAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	echoHandler(w, r)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// echoHandler is the main endpoint that returns everything.
//
// Request-level controls (query parameter wins over header):
//   - format=json|text
//   - fields=ip.country,client_hello.sni,...   (dot paths; empty = everything)
func echoHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	bodyBytes, readErr := io.ReadAll(r.Body)
	r.Body.Close()
	if readErr != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	resp := EchoResponse{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Method:      r.Method,
		Scheme:      scheme,
		Host:        r.Host,
		RemoteAddr:  r.RemoteAddr,
		Path:        r.URL.Path,
		Query:       r.URL.RawQuery,
		HTTPVersion: r.Proto,
		Headers:     r.Header,
		Body:        string(bodyBytes),
		BodyLength:  len(bodyBytes),
	}

	// TLS state is available on r.TLS for https requests
	if r.TLS != nil {
		resp.TLS = extractTLSInfoFromState(r.TLS)
	}

	// ClientHello: prefer THIS connection's capture, fall back to the global
	// (used by tests / non-CLIENT connections).
	resp.ClientHello = &ClientHelloInfo{}
	if snap := helloSnapshotFromConn(r); snap.Payload != nil {
		resp.ClientHello.RawRecord = base64.StdEncoding.EncodeToString(snap.RecordBytes())
		resp.ClientHello.RecordLength = len(snap.RecordBytes())
		resp.ClientHello.RecordCount = snap.RecordCount()
		resp.ClientHello.RecordVersion = snap.RecordVersion
		populateClientHelloWith(resp.ClientHello, snap.Payload)
	} else {
		rawHello := getCapturedClientHello()
		populateClientHelloWith(resp.ClientHello, rawHello)
		if len(rawHello) > 0 {
			resp.ClientHello.RawRecord = base64.StdEncoding.EncodeToString(rawHello)
			resp.ClientHello.RecordLength = len(rawHello)
			resp.ClientHello.RecordCount = 1
		}
	}
	if resp.ClientHello.SNI == "" && r.TLS != nil {
		resp.ClientHello.SNI = r.TLS.ServerName
	}

	// Client identification: TLS fingerprint + User-Agent (+ header-set hint).
	// The header set is a weak signal used to refine confidence, not the answer.
	showClient := GetConfig("show_client") != "false"
	if showClient {
		ua := r.Header.Get("User-Agent")
		if ci := identifyClient(resp.ClientHello, ua); ci != nil {
			ci.HeaderSet = headerSignature(r.Header)
			if browserLikeHeaders(r.Header) {
				ci.Matches = append(ci.Matches, "header set looks browser-like")
			}
			resp.Client = ci
		}
	}

	// HTTP-layer fingerprint (JA4H): separates clients that share a TLS stack.
	showJA4H := GetConfig("show_ja4h") != "false"
	if showJA4H {
		resp.JA4H = ja4hFingerprint(r)
	}

	// Expose JA3/JA4 once (tls object mirrors client_hello).
	if resp.ClientHello.JA3 != "" {
		if resp.TLS == nil {
			resp.TLS = &TLSFingerprint{}
		}
		resp.TLS.JA3String = resp.ClientHello.JA3
		resp.TLS.JA3Hash = resp.ClientHello.JA3Hash
		resp.TLS.JA4 = resp.ClientHello.JA4
		resp.TLS.JA4R = resp.ClientHello.JA4R
		resp.TLS.JA4O = resp.ClientHello.JA4O
	}

	// Best-effort IP / ASN / geolocation (provider configurable, cached)
	if ip := getClientIP(r); ip != "" {
		resp.IP = fetchIPInfo(ip)
	}

	// Persist minimal query log via SQLite (real path). Replays are synthetic
	// and must not inflate the production counters.
	if resp.IP != nil && !isReplay(r) {
		LogQuery(r.Method, r.URL.Path, resp.IP.IP, resp.IP.ConnectionType, resp.IP.Country)
	}

	// Admin-configurable default field toggles (request params can only narrow,
	// never widen, what the admin exposes).
	showJA3 := GetConfig("show_ja3") != "false"
	showIP := GetConfig("show_ip") != "false"
	showRaw := GetConfig("show_raw") != "false"
	showBody := GetConfig("show_body") != "false"

	if !showJA3 && resp.TLS != nil {
		resp.TLS.JA3String, resp.TLS.JA3Hash = "", ""
	}
	if !showIP {
		resp.IP = nil
	}
	if !showRaw && resp.ClientHello != nil {
		resp.ClientHello.Raw = ""
		resp.ClientHello.RawHex = ""
		resp.ClientHello.RawRecord = ""
	}
	if !showBody {
		resp.Body = ""
	}
	if !showClient {
		resp.Client = nil
	}
	if !showJA4H {
		resp.JA4H = ""
	}

	format := requestParam(r, "format", "X-Echo-Format", GetConfig("default_format"))
	fields := requestParam(r, "fields", "X-Echo-Fields", "")
	payload, contentType, err := serializeEcho(resp, format, fields)
	if err != nil {
		http.Error(w, "failed to encode response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType)
	// Keep the historical permissive CORS default unless an operator configured
	// an explicit origin list (the security middleware sets that header).
	if w.Header().Get("Access-Control-Allow-Origin") == "" && GetConfig("cors_origins") == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.Write(payload)

	clientName := ""
	if resp.Client != nil {
		clientName = resp.Client.Name
	}
	log.Printf("%s %s %s %d %s client=%s", r.Method, r.URL.Path, r.RemoteAddr, http.StatusOK, time.Since(start), clientName)
}

// requestParam resolves a control value as: query param > header > fallback.
func requestParam(r *http.Request, queryKey, headerKey, fallback string) string {
	if v := strings.TrimSpace(r.URL.Query().Get(queryKey)); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get(headerKey)); v != "" {
		return v
	}
	return fallback
}

// configHandler allows admin to read/write return-field toggles (JWT protected)
func configHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg := map[string]string{
			"show_ja3":           GetConfig("show_ja3"),
			"show_ip":            GetConfig("show_ip"),
			"show_raw":           GetConfig("show_raw"),
			"show_body":          GetConfig("show_body"),
			"show_client":        GetConfig("show_client"),
			"show_ja4h":          GetConfig("show_ja4h"),
			"require_token":      GetConfig("require_token"),
			"allow_registration": GetConfig("allow_registration"),
			"enable_online_geo":  GetConfig("enable_online_geo"),
			"geo_provider":       GetConfig("geo_provider"),
			"geo_cache_ttl":      GetConfig("geo_cache_ttl"),
			"default_format":     GetConfig("default_format"),
			"ipinfo_token":       GetConfig("ipinfo_token"),
			"api_token":          GetConfig("api_token"),
			// Console / edge-operations settings.
			"site_name":           GetConfig("site_name"),
			"site_description":    GetConfig("site_description"),
			"timezone":            GetConfig("timezone"),
			"locale":              GetConfig("locale"),
			"density":             GetConfig("density"),
			"maintenance_mode":    GetConfig("maintenance_mode"),
			"maintenance_message": GetConfig("maintenance_message"),
			"ip_allowlist":        GetConfig("ip_allowlist"),
			"ip_denylist":         GetConfig("ip_denylist"),
			"rate_limit_per_min":  GetConfig("rate_limit_per_min"),
			"cors_origins":        GetConfig("cors_origins"),
			"security_headers":    GetConfig("security_headers"),
			"body_limit_kb":       GetConfig("body_limit_kb"),
			"log_retention_days":  GetConfig("log_retention_days"),
		}
		// Read-only accounts may inspect settings but must not learn secrets.
		if u := currentUser(r); u == nil || u.Role != RoleAdmin {
			if cfg["ipinfo_token"] != "" {
				cfg["ipinfo_token"] = "***"
			}
			if cfg["api_token"] != "" {
				cfg["api_token"] = "***"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
		return
	}
	if r.Method == http.MethodPost {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		changed := make([]string, 0, len(body))
		for k, v := range body {
			if err := SetConfig(k, v); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			changed = append(changed, k)
		}
		sort.Strings(changed)
		RecordAudit(r, "config.update", strings.Join(changed, ","), "")
		emitEvent("config.update", map[string]any{"actor": userName(r), "keys": changed})
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// writeJSON writes a JSON response with the standard content type.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// logsHandler returns recent query logs for the admin UI (JWT protected).
// ?limit=N (max 500) controls how many rows are returned.
func logsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f := parseLogFilter(r)
	if f.Limit > 2000 {
		f.Limit = 2000
	}
	writeJSON(w, fetchLogs(f))
}

// statsHandler feeds the dashboard counters (any authenticated account).
func statsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, GetStats())
}

// newSPAHandler serves static files from fsys and falls back to index.html for
// client-side routes. Paths that clearly name an asset (they carry an
// extension) still 404 when missing, so a broken build is visible instead of
// silently returning HTML.
func newSPAHandler(fsys fs.FS) http.Handler {
	files := http.FileServer(http.FS(fsys))
	index, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		log.Fatalf("embedded frontend index.html missing: %v", err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || name == "." {
			files.ServeHTTP(w, r)
			return
		}
		if st, err := fs.Stat(fsys, name); err == nil && !st.IsDir() {
			files.ServeHTTP(w, r)
			return
		}
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}

func extractTLSInfoFromState(state *tls.ConnectionState) *TLSFingerprint {
	if state == nil {
		return nil
	}
	return &TLSFingerprint{
		Version:     tlsVersionToString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ServerName:  state.ServerName,
		ALPN:        state.NegotiatedProtocol,
		Resumed:     state.DidResume,
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

// getClientIP delegates to the single shared implementation.
func getClientIP(r *http.Request) string { return extractClientIP(r) }

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
