package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Client identification: combines the TLS fingerprint (JA4/JA3) with the
// User-Agent to answer "which client is making this request?" — and just as
// importantly, to flag when the two disagree (a crawler pretending to be a
// browser). The TLS fingerprint is the harder-to-spoof signal: a real Chrome
// always produces a Chrome-like JA4 regardless of what the UA claims.
//
// The fingerprint table below is data-driven: every entry was measured from a
// real client on this machine (curl, wget, python-requests, node, java,
// openssl, Go, Chromium, Firefox) through this very server. JA3 hashes are the
// MD5 of the JA3 string (the industry-standard "JARM of the client").

// clientID is an intermediate result carrying a family + candidate names.
type clientID struct {
	names      []string // candidate names, best first (empty when unknown)
	family     string   // browser | cli | library | runtime | tool | bot | unknown
	version    string
	conf       float64
	evidence   []string
	notes      []string
	candidates []ClientCandidate
	dbObs      uint64
	dbPrefix   bool
	source     string // ja4db | ja4db_prefix | ja4db:<provider> | ja4_measured | ja3_measured | ja4_heuristic
}

func (c clientID) id() ClientInfo {
	src := c.source
	if src == "" {
		src = "ja4_heuristic"
	}
	signal := src + "+user_agent"
	if src == "user_agent" {
		signal = "user_agent" // only the UA contributed
	}
	return ClientInfo{
		Name:           firstOr(c.names, ""),
		Family:         c.family,
		Version:        c.version,
		Confidence:     c.conf,
		Signal:         signal,
		Source:         src,
		Matches:        c.evidence,
		Notes:          c.notes,
		Candidates:     c.candidates,
		DBObservations: c.dbObs,
	}
}

// ClientInfo is the public per-request client identification.
type ClientInfo struct {
	Name           string            `json:"name,omitempty"`            // best-guess client, e.g. "curl" or "Chrome"
	Family         string            `json:"family,omitempty"`          // browser | cli | library | runtime | tool | bot | unknown
	Version        string            `json:"version,omitempty"`         // e.g. "8.5.0", "21.x", "120+"
	Confidence     float64           `json:"confidence"`                // 0..1
	Signal         string            `json:"signal,omitempty"`          // which signals contributed
	Source         string            `json:"source,omitempty"`          // ja4db | ja4db_prefix | ja4db:<provider> | ja4_measured | ja3_measured | user_agent | ja4_heuristic
	Matches        []string          `json:"matches,omitempty"`         // human-readable evidence
	Candidates     []ClientCandidate `json:"candidates,omitempty"`      // other clients seen with this fingerprint
	DBObservations uint64            `json:"db_observations,omitempty"` // JA4DB observation count behind the match
	Spoofed        bool              `json:"spoofed,omitempty"`         // UA and TLS disagree
	Notes          []string          `json:"notes,omitempty"`           // caveats (version drift, etc.)
	HeaderSet      string            `json:"header_set_hash,omitempty"` // hash of which headers were present
}

// ---------------------------------------------------------------------------
// TLS fingerprint table

// ja4 table: exact JA4 fingerprint -> client. Measured from real clients.
// Key format: name|family|version|confidence (confidence as 0-100 integer).
var ja4Exact = map[string]string{
	// curl 8.5.0 (OpenSSL) — ALPN offered
	"t13i3111h2_e8f1e7e78f70_b26ce05bbdd6": "curl|cli|8.x|88",
	// python-requests / urllib3 (OpenSSL) — same crypto as curl, ALPN http/1.1 only.
	// Cannot be named further without the UA (they share this JA4).
	"t13i3111h1_e8f1e7e78f70_b26ce05bbdd6": "OpenSSL HTTP client|http_client|1.1|62",
	// wget 1.21.4 (GnuTLS) — 75 ciphers, no ALPN.
	"t13i751000_479067518aa3_fb8d5ffd48c1": "wget|cli|1.21.x|85",
	// Node.js (OpenSSL, stable for years)
	"t13i590900_a33745022dd6_1f22a2ca17c4": "node|runtime|18+|92",
	// Java 21 (OpenJDK, also ~17)
	"t13i311100_1d947a95fc68_7e1102d2036b": "Java|runtime|17+|88",
	// OpenSSL s_client
	"t13d311000_e8f1e7e78f70_1f22a2ca17c4": "openssl|cli|3.x|84",
	// Go net/http (Go 1.24+ default post-quantum key share). SNI variant.
	// NOTE: the post-quantum key share is also sent by modern Chrome, and JA4DB
	// sees plenty of crawlers wearing a Chrome UA with this fingerprint, so the
	// database contribution is what tells us how exclusive it really is.
	"t13d131100_f57a46bbacb6_ab7e3b40a677": "Go net/http|runtime|1.24+|90",
	"t13i131100_f57a46bbacb6_ab7e3b40a677": "Go net/http|runtime|1.24+|90",
	// Plain-Transport HTTP client to an IP literal: no SNI (10 extensions, head ..000).
	"t13i131000_f57a46bbacb6_ab7e3b40a677": "Go net/http|runtime|1.24+|90",
	// Chromium / Chrome (measured: Chromium 156 headless)
	"t13i1516h2_8daaf6152771_cb7bf5808d99": "Chrome|browser|120+|90",
}

// ja3 table: exact JA3 hash -> client, for clients whose JA3 is stable
// (no GREASE). Browsers send GREASE, so their JA3 varies run-to-run and is
// matched by JA4 instead.
var ja3Exact = map[string]string{
	"78f0dc5ac5b19daf131a133cfdee9691": "curl|cli|8.x|80", // curl / python-requests, UA disambiguates
	"ceae6388daceebc11811eebcebb26df1": "wget|cli|1.21.x|82",
	"6521bd74aad3476cdb3daa827288ec35": "node|runtime|18+|92",
	"ea0154154790b24e85b5cc9676622c9c": "java|runtime|17+|88",
	"a3afc2c46ba4a7d7fbe1cfb7a3031c2f": "openssl|cli|3.x|80",
	"9b7dcdf3f997f1fb7b4409c94cb7ef36": "go|runtime|1.24+|90",
}

// splitFPRule decodes "name|family|version|conf" entries.
func splitFPRule(s string) (name, family, version string, conf float64) {
	parts := strings.Split(s, "|")
	if len(parts) < 4 {
		return "", "unknown", "", 0
	}
	conf = float64(atoi(parts[3])) / 100
	return parts[0], parts[1], parts[2], conf
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// matchTLS identifies the client from the TLS fingerprint alone.
//
// Priority: JA4DB (exact, then prefix — thousands of real-world fingerprints)
// > locally measured exact JA4 > exact JA3 (no GREASE) > family heuristics.
// A JA4DB hit is authoritative when it is unambiguous; the locally measured
// table then only contributes confirmation, because a single measurement of
// ours cannot outvote a fingerprint thousands of clients share.
func matchTLS(ch *ClientHelloInfo) clientID {
	if ch == nil {
		return clientID{}
	}
	db := lookupJA4(ch.JA4)
	if r, ok := ja4Exact[ch.JA4]; ok {
		n, f, v, c := splitFPRule(r)
		measured := clientID{names: []string{n}, family: f, version: v, conf: c,
			evidence: []string{"JA4 exact match: " + ch.JA4}, source: "ja4_measured"}
		if db == nil {
			return measured
		}
		return mergeMeasured(measured, db)
	}
	if db != nil {
		return clientIDFromDB(db)
	}
	if r, ok := ja3Exact[ch.JA3Hash]; ok {
		n, f, v, c := splitFPRule(r)
		return clientID{names: []string{n}, family: f, version: v, conf: c,
			evidence: []string{"JA3 exact match (hash " + ch.JA3Hash[:12] + ")"},
			source:   "ja3_measured"}
	}

	// Heuristic family detection for unknown fingerprints.
	var ev []string
	grease := ch.HasGREASE
	h2 := false
	for _, a := range ch.ALPN {
		if strings.EqualFold(a, "h2") {
			h2 = true
		}
	}
	if grease {
		// GREASE + TLS 1.3 + many extensions is a browser signature.
		c := 0.55
		name, fam := "browser", "browser"
		if h2 {
			name, fam = "browser (h2)", "browser"
		}
		ev = append(ev, "GREASE present ⇒ browser-like TLS")
		return clientID{names: []string{name}, family: fam, version: "?", conf: c, evidence: ev,
			source: "ja4_heuristic"}
	}
	for _, g := range ch.KeyShareGroups {
		if g == 4588 { // X25519MLKEM768, Go 1.24+ default
			return clientID{names: []string{"go"}, family: "runtime", version: "1.24+", conf: 0.6,
				evidence: append(ev, "X25519MLKEM768 key share ⇒ modern Go/BoringSSL"),
				source:   "ja4_heuristic"}
		}
	}
	for _, g := range ch.SupportedGroups {
		if g >= 256 && g <= 260 { // FFDHE groups: Java's TLS stack
			return clientID{names: []string{"java"}, family: "runtime", version: "?", conf: 0.6,
				evidence: append(ev, "FFDHE groups + Java extension set"),
				source:   "ja4_heuristic"}
		}
	}
	if len(ch.Extensions) == 9 && !grease && !h2 && containsAll16(ch.Extensions, []uint16{0x000b, 0x000a, 0x0023, 0x0016, 0x0017, 0x000d, 0x002b, 0x002d, 0x0033}) {
		return clientID{names: []string{"node"}, family: "runtime", version: "?", conf: 0.7,
			evidence: append(ev, "distinctive Node.js extension set"),
			source:   "ja4_heuristic"}
	}
	return clientID{}
}

// clientIDFromDB turns a JA4DB lookup into the TLS-side identification.
func clientIDFromDB(m *dbMatch) clientID {
	ev := []string{ja4dbEvidence(m)}
	if m.Note != "" {
		ev = append(ev, m.Note)
	}
	version := m.Version
	if version != "" && m.Exact {
		// The version comes from observations, not from this connection: the
		// caller may run an older or newer build sharing the same fingerprint.
		ev = append(ev, "version range observed in JA4DB: "+version)
		version += " (observed)"
	}
	src := "ja4db"
	if !m.Exact {
		src = "ja4db_prefix"
	}
	if m.Provider != "" && m.Provider != "builtin" {
		// A custom provider (local file or cloud-synced library) supplied the
		// evidence; name it so the operator can see which library decided.
		src += ":" + safeName(m.Provider)
	}
	return clientID{
		names:      []string{m.Name},
		family:     m.Family,
		version:    version,
		conf:       m.Confidence,
		evidence:   ev,
		candidates: m.Candidates,
		dbObs:      m.Observations,
		dbPrefix:   !m.Exact,
		source:     src,
	}
}

// isGenericTLSName reports whether a TLS-side name cannot identify a client by
// itself (volunteered by the parser rather than measured: "browser", "browser
// (h2)", "OpenSSL HTTP client").
func isGenericTLSName(name string) bool {
	return name == "" || strings.Contains(name, "browser") || strings.HasPrefix(name, "OpenSSL")
}

// mergeMeasured combines our own controlled measurement with the wider JA4DB
// evidence for the same fingerprint.
//
// The measurement is ground truth (we ran that client against this server), so
// it names the fingerprint — EXCEPT when it is generic ("OpenSSL HTTP client"),
// where the database's votes are more specific. Conversely, the database tells
// us how *exclusive* the fingerprint is: JA4DB vote shares come from submitted
// User-Agents, and the same TLS stack really is shared by unrelated clients
// (Go 1.24+ and Chrome both send the post-quantum X25519MLKEM768 key share).
// When the top database candidate disagrees with the measurement we say so
// instead of hiding it, and trim confidence accordingly.
func mergeMeasured(measured clientID, m *dbMatch) clientID {
	mname := firstOr(measured.names, "")

	// A generic measurement carries no naming information; let the database name.
	if m.Exact && isGenericTLSName(mname) {
		out := clientIDFromDB(m)
		out.evidence = append(out.evidence, measured.evidence...)
		return out
	}

	out := measured
	out.source = "ja4_measured"
	out.candidates = m.Candidates
	out.dbObs = m.Observations
	out.evidence = append(out.evidence, ja4dbEvidence(m))
	if m.Note != "" {
		out.evidence = append(out.evidence, m.Note)
	}

	same := strings.EqualFold(m.Name, mname)
	switch {
	case same:
		out.evidence = append(out.evidence,
			"JA4DB observations agree with the locally measured "+mname+" fingerprint")
		if out.conf < 0.9 {
			out.conf = minf(0.9, out.conf+0.05)
		}
	case m.Confidence >= 0.6:
		top := m.Candidates[0].Share
		out.notes = append(out.notes, "this TLS fingerprint is shared: JA4DB attributes "+
			percent(top)+" of its "+strconv.FormatUint(m.Observations, 10)+" observations to "+m.Name+
			", and this server measured "+mname+" with the same fingerprint — TLS alone cannot separate them")
		if out.conf > 0.87 {
			out.conf = 0.87
		}
	}
	return out
}

func containsAll16(hay []uint16, needle []uint16) bool {
	for _, n := range needle {
		found := false
		for _, h := range hay {
			if h == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// User-Agent parsing

type uaResult struct {
	name, family, version string
	conf                  float64
}

// parseUserAgent recognizes common HTTP clients from their User-Agent line.
// Order matters: browser tokens must be checked before the generic "Mozilla".
func parseUserAgent(ua string) uaResult {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return uaResult{}
	}
	lower := strings.ToLower(ua)
	has := func(tok string) bool { return strings.Contains(lower, tok) }
	ver := func(tok string) string { return versionAfter(lower, tok) }

	switch {
	case has("curl/"):
		return uaResult{"curl", "cli", ver("curl/"), 0.95}
	case has("wget/"):
		return uaResult{"wget", "cli", ver("wget/"), 0.95}
	case has("go-http-client/"):
		// "Go-http-client/1.1" is the HTTP version, not the Go release.
		return uaResult{"Go net/http", "runtime", "", 0.95}
	case has("python-requests/"):
		return uaResult{"python-requests", "library", ver("python-requests/"), 0.95}
	case has("aiohttp/"):
		return uaResult{"aiohttp", "library", ver("aiohttp/"), 0.95}
	case has("httpx/"):
		return uaResult{"httpx", "library", ver("httpx/"), 0.93}
	case has("node-fetch"):
		return uaResult{"node-fetch", "library", "", 0.9}
	case has("okhttp/"):
		return uaResult{"okhttp", "library", ver("okhttp/"), 0.95}
	case has("postmanruntime/"):
		return uaResult{"Postman", "tool", ver("postmanruntime/"), 0.95}
	case has("java/"):
		return uaResult{"Java", "runtime", ver("java/"), 0.95}
	case has("go-http-client"): // any other Go
		return uaResult{"Go net/http", "runtime", "", 0.88}
	case has("googlebot"):
		return uaResult{"Googlebot", "bot", "", 0.9}
	case has("bingbot"):
		return uaResult{"Bingbot", "bot", "", 0.9}
	case has("ahrefsbot"):
		return uaResult{"AhrefsBot", "bot", "", 0.9}
	case has("semrushbot"):
		return uaResult{"SemrushBot", "bot", "", 0.9}
	case has("headlesschrome"):
		return uaResult{"HeadlessChrome", "browser", ver("headlesschrome/"), 0.9}
	case has("edg/"):
		return uaResult{"Edge", "browser", ver("edg/"), 0.9}
	case has("opr/"):
		return uaResult{"Opera", "browser", ver("opr/"), 0.9}
	case has("chrome/"):
		return uaResult{"Chrome", "browser", ver("chrome/"), 0.93}
	case has("firefox/"):
		return uaResult{"Firefox", "browser", ver("firefox/"), 0.93}
	case has("safari") && has("applewebkit"):
		return uaResult{"Safari", "browser", ver("version/"), 0.8}
	case has("mozilla"):
		return uaResult{"generic browser", "browser", "", 0.3}
	}
	return uaResult{}
}

// versionAfter returns the token following "tok" up to a space or "/"-separator.
func versionAfter(lower, tok string) string {
	i := strings.Index(lower, tok)
	if i < 0 {
		return ""
	}
	rest := lower[i+len(tok):]
	rest = strings.TrimLeft(rest, " ")
	end := strings.IndexAny(rest, " ;,()\t\r\n\"")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end]
}

// ---------------------------------------------------------------------------
// Combination

// identifyClient produces the final answer. TLS is the trust anchor: when the
// UA claims a different family than the TLS fingerprint, we mark the request
// as spoofed and trust the TLS side.
func identifyClient(ch *ClientHelloInfo, ua string) *ClientInfo {
	tlsID := matchTLS(ch)
	uaID := parseUserAgent(ua)

	if tlsID.family == "" && uaID.name == "" {
		return nil // nothing known about this client
	}

	// Build evidence.
	var matches []string
	if tlsID.conf > 0 {
		matches = append(matches, tlsID.evidence...)
	}
	if uaID.name != "" {
		matches = append(matches, "User-Agent: "+truncateStr(ua, 80))
	}

	// Determine families for the mismatch check (unknown side gets a pass).
	tlsFam, uaFam := tlsID.family, uaID.family
	if tlsFam == "" {
		tlsFam = "unknown"
	}
	if uaFam == "" {
		uaFam = "unknown"
	}
	spoofed := familyMismatch(tlsFam, uaFam)

	// A "generic" TLS match (browser-like TLS, or the shared OpenSSL stack used
	// by curl/python/wget) cannot name the client by itself; the UA or a more
	// specific fingerprint must.
	tlsGeneric := isGenericTLSName(firstOr(tlsID.names, ""))

	// Pick the answer. When the UA lies (spoofed), the TLS fingerprint is the
	// answer — it is far harder to forge, and reporting the claimed UA here
	// would launder the disguise. Otherwise take the more specific of the two,
	// preferring the UA on a tie (it carries versions). One exception: when a
	// user-configured fingerprint library (local file or cloud-synced) named
	// the client and the UA agrees, the library is the operator's authoritative
	// signal and stays the reported source — the UA only supplies its version.
	uaIDEntry := clientID{names: []string{uaID.name}, family: uaID.family,
		version: uaID.version, conf: uaID.conf, evidence: matches, source: "user_agent"}
	customDB := strings.HasPrefix(tlsID.source, "ja4db:") // a non-builtin provider decided
	tlsUASameName := uaID.name != "" && strings.EqualFold(firstOr(tlsID.names, ""), uaID.name)
	var out clientID
	switch {
	case spoofed && tlsID.conf > 0:
		out = tlsID
	case customDB && !spoofed && tlsUASameName:
		out = tlsID
	case uaID.name != "" && uaID.conf >= tlsID.conf:
		out = uaIDEntry
		out.notes = append(out.notes, tlsID.notes...)
		// The fingerprint may be shared by other clients; keep that context
		// even when the UA names the winner.
		if len(out.candidates) == 0 {
			out.candidates = tlsID.candidates
			out.dbObs = tlsID.dbObs
		}
		if tlsID.conf > out.conf {
			out.conf = tlsID.conf
		}
	case !tlsGeneric:
		out = tlsID
	case uaID.name != "":
		out = uaIDEntry
	case tlsID.conf > 0:
		out = tlsID
	default:
		return nil
	}
	out.evidence = matches
	// Version resolution:
	//  - when TLS and the UA name the same client, the UA's own version is the
	//    version of THIS caller (a JA4DB range describes other people's builds);
	//  - when the UA carries no version (or only an HTTP version, e.g.
	//    "Go-http-client/1.1"), fall back to the fingerprint's version.
	sameName := uaID.name != "" && strings.EqualFold(firstOr(out.names, ""), uaID.name)
	switch {
	case sameName && uaID.version != "" && !spoofed:
		out.version = uaID.version
	case out.version == "" || out.version == "?":
		if tlsID.version != "" && tlsID.version != "?" {
			out.version = tlsID.version
		} else {
			out.version = ""
		}
	}

	info := out.id()
	info.Spoofed = spoofed
	if spoofed {
		// Name the truth (TLS) and the claim (UA) side by side, so the reader
		// sees both without having to dig into the raw headers.
		tlsLabel := firstOr(tlsID.names, tlsFam)
		info.Notes = append(info.Notes, "TLS fingerprint says "+tlsLabel+" ("+tlsFam+
			") but the User-Agent claims "+firstOr([]string{uaID.name}, "another client")+" ("+uaFam+
			") — the UA is very likely spoofed")
	}
	if !tlsGeneric && uaID.name != "" && !spoofed {
		// Both signals agree on a concrete client; record that explicitly.
		info.Matches = append(info.Matches, "TLS family and User-Agent agree")
	}
	return &info
}

// familyMismatch reports whether TLS and UA claim incompatible client types.
func familyMismatch(tlsFam, uaFam string) bool {
	if tlsFam == "unknown" || uaFam == "unknown" {
		return false
	}
	if tlsFam == uaFam {
		return false
	}
	// A browser page or a browser UA never shares a request with a bare
	// crypto/library stack, in either direction.
	if tlsFam == "browser" || uaFam == "browser" {
		return true
	}
	// cli / library / http_client all describe scripted, non-browser clients
	// whose TLS stacks legitimately overlap (curl, python, wget, node…).
	scripted := map[string]bool{"cli": true, "library": true, "http_client": true}
	if scripted[tlsFam] && scripted[uaFam] {
		return false
	}
	return tlsFam != uaFam
}

// ---------------------------------------------------------------------------
// helpers

func firstOr(vs []string, def string) string {
	if len(vs) > 0 && vs[0] != "" {
		return vs[0]
	}
	return def
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// headerSignature returns a short hash of which request headers are present
// (cases normalized, order-independent — Go's http.Header is a map, so header
// *order* is not recoverable server-side). Browsers send a far richer header
// set than CLI tools, so this is a useful weak signal for spoof detection.
func headerSignature(h map[string][]string) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "|")))
	return hex.EncodeToString(sum[:])[:12]
}

// clientHeaderHints checks whether the header set looks like a real browser
// (rich sec-* / accept-* set) versus a thin scripted client.
func browserLikeHeaders(h map[string][]string) bool {
	sec := 0
	for k := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "sec-") || strings.HasPrefix(lk, "accept-") {
			sec++
		}
	}
	return sec >= 3
}

// minf returns the smaller of two floats.
func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// percent renders a 0..1 share as an integer percentage.
func percent(f float64) string {
	return strconv.Itoa(int(f*100+0.5)) + "%"
}
