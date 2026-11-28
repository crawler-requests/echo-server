// Command ghcr-prune keeps only the newest N releases of a container package
// on GHCR.
//
// A GHCR package version is not a release. One multi-arch push (Buildx with
// attestations) creates five of them: the tagged index manifest that carries
// `1.2.3`, `1.2`, `1` and `latest`, one child manifest per platform
// (linux/amd64, linux/arm64), and one attestation manifest per platform.
// Deleting "the oldest version" therefore removes a fragment of a release,
// not a release, and a count of versions cannot express "keep the last three
// releases". This tool groups the fragments back into releases and deletes
// whole releases.
//
// A release is identified by its tagged version (the index manifest). Untagged
// versions attach to the tagged version nearest in creation time, because one
// push creates its fragments within seconds of each other.
//
// Two guarantees:
//
//   - The newest `-keep` releases are never touched, and neither are their
//     fragment manifests.
//   - A version carrying a floating tag (`latest`, `1`, `1.2`) is never deleted
//     while it is the only pointer to that alias: deleting the last version
//     tagged `1` when `2.0.0` ships would break an operator's pin.
//
// Defaults to a dry run; `-apply` performs the deletions. The token needs to
// read and delete package versions — in Actions the default GITHUB_TOKEN with
// `packages: write` is enough (verified against api.github.com from a workflow:
// list 200, delete 204).
//
// Usage:
//
//	GH_TOKEN=$GITHUB_TOKEN go run ./tools/ghcr-prune -package echo-server -keep 3
//	GH_TOKEN=$GITHUB_TOKEN go run ./tools/ghcr-prune -package echo-server -keep 3 -apply
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// defaultAPI is GitHub's REST endpoint. The -api flag exists so tests can point
// the tool at an httptest server.
const defaultAPI = "https://api.github.com"

// floatingTag matches the aliases docker/metadata-action maintains next to the
// exact version: `latest`, `1` and `1.2`. They must keep resolving to a release.
var floatingTag = regexp.MustCompile(`^(latest|\d+|\d+\.\d+)$`)

// version is the subset of the package-version REST payload this tool needs.
type version struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Tags      []string  `json:"-"`
}

// tagsOf extracts metadata.container.tags, which the REST response nests under
// an optional metadata object (absent for versions that never carried a tag).
func tagsOf(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var meta struct {
		Container struct {
			Tags []string `json:"tags"`
		} `json:"container"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil
	}
	return meta.Container.Tags
}

func (v version) String() string {
	tags := strings.Join(v.Tags, ",")
	if tags == "" {
		tags = "<untagged>"
	}
	return fmt.Sprintf("%d %s %s (%s)", v.ID, v.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"), tags, shortName(v.Name))
}

func shortName(name string) string {
	name = strings.TrimPrefix(name, "sha256:")
	if len(name) > 12 {
		return name[:12]
	}
	return name
}

// client talks to the packages REST API.
type client struct {
	api   string
	owner string
	pkg   string
	token string
	http  *http.Client
}

func (c client) endpoint(suffix string) string {
	return fmt.Sprintf("%s/orgs/%s/packages/container/%s%s",
		strings.TrimRight(c.api, "/"), url.PathEscape(c.owner), url.PathEscape(c.pkg), suffix)
}

func (c client) do(ctx context.Context, method, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return c.http.Do(req)
}

// listVersions walks every page of package versions. GHCR returns them newest
// first, but the caller sorts explicitly rather than trusting that order.
func (c client) listVersions(ctx context.Context) ([]version, error) {
	var all []version
	for page := 1; ; page++ {
		resp, err := c.do(ctx, http.MethodGet, c.endpoint("/versions?per_page=100&page="+strconv.Itoa(page)))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			// A package with no versions yet: nothing to prune, not an error.
			return nil, nil
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("list versions: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var raw []struct {
			ID        int64           `json:"id"`
			Name      string          `json:"name"`
			CreatedAt time.Time       `json:"created_at"`
			Metadata  json.RawMessage `json:"metadata"`
		}
		err = json.NewDecoder(resp.Body).Decode(&raw)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode versions page %d: %w", page, err)
		}
		for _, r := range raw {
			all = append(all, version{ID: r.ID, Name: r.Name, CreatedAt: r.CreatedAt.UTC(), Tags: tagsOf(r.Metadata)})
		}
		if len(raw) < 100 {
			return all, nil
		}
	}
}

// deleteVersion removes one package version, tags included.
func (c client) deleteVersion(ctx context.Context, id int64) error {
	resp, err := c.do(ctx, http.MethodDelete, c.endpoint("/versions/"+strconv.FormatInt(id, 10)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("delete version %d: HTTP %d: %s", id, resp.StatusCode, strings.TrimSpace(string(body)))
}

// release is one publish: its tagged index manifest plus the untagged child
// and attestation manifests created by the same push.
type release struct {
	Index     version
	Fragments []version
}

// plan is the retention decision, kept free of HTTP so tests can assert it.
type plan struct {
	Keep    []release
	Drop    []release
	Rescued []version // floating-tag versions kept beyond the window
}

// versionsToDelete flattens the plan into the versions that will be removed.
func (p plan) versionsToDelete() []version {
	var out []version
	for _, r := range p.Drop {
		out = append(out, r.Index)
		out = append(out, r.Fragments...)
	}
	return out
}

// decide applies the retention policy. It is pure: same versions and keep in,
// same plan out.
func decide(versions []version, keep int) plan {
	sorted := slices.Clone(versions)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})

	var tagged, untagged []version
	for _, v := range sorted {
		if len(v.Tags) > 0 {
			tagged = append(tagged, v)
		} else {
			untagged = append(untagged, v)
		}
	}

	p := plan{}
	if len(tagged) <= keep {
		// The window is not yet full: every release and every fragment stays.
		for _, v := range tagged {
			p.Keep = append(p.Keep, release{Index: v})
		}
		for _, u := range untagged {
			p.keepFragment(u, tagged)
		}
		return p
	}

	cut := len(tagged) - keep
	for i, v := range tagged {
		if i >= cut {
			p.Keep = append(p.Keep, release{Index: v})
		} else {
			p.Drop = append(p.Drop, release{Index: v})
		}
	}

	// Rescue a falling-out version whose floating tag would otherwise vanish
	// from the package: `1` and `1.2` must keep resolving for people who pin.
	kept := map[string]bool{}
	for _, r := range p.Keep {
		for _, t := range r.Index.Tags {
			kept[t] = true
		}
	}
	var remaining []release
	for _, r := range p.Drop {
		alias := ""
		for _, t := range r.Index.Tags {
			if floatingTag.MatchString(t) && !kept[t] {
				alias = t
			}
		}
		if alias != "" {
			p.Rescued = append(p.Rescued, r.Index)
			p.Keep = append(p.Keep, r)
			for _, t := range r.Index.Tags {
				kept[t] = true
			}
			continue
		}
		remaining = append(remaining, r)
	}
	p.Drop = remaining

	// Fragments follow their index: kept releases keep theirs, dropped releases
	// lose theirs. A fragment with no tagged version near it is orphaned (its
	// index was deleted earlier) and is removed only if it predates the
	// window's oldest kept release.
	for _, u := range untagged {
		if p.keepFragment(u, tagged) {
			continue
		}
		if idx := p.indexOfDropped(nearest(u, tagged).ID, remaining); idx >= 0 {
			p.Drop[idx].Fragments = append(p.Drop[idx].Fragments, u)
			continue
		}
	}
	return p
}

// keepFragment attaches an untagged version to its nearest kept release and
// reports whether that happened.
func (p *plan) keepFragment(u version, tagged []version) bool {
	n := nearest(u, tagged)
	for i := range p.Keep {
		if p.Keep[i].Index.ID == n.ID {
			p.Keep[i].Fragments = append(p.Keep[i].Fragments, u)
			return true
		}
	}
	return false
}

// indexOfDropped finds the dropped release with the given index id.
func (p plan) indexOfDropped(id int64, dropped []release) int {
	for i := range dropped {
		if dropped[i].Index.ID == id {
			return i
		}
	}
	return -1
}

// nearest returns the tagged version closest in creation time to u. With no
// tagged versions at all it returns the zero version.
func nearest(u version, tagged []version) version {
	var best version
	bestDelta := time.Duration(1<<63 - 1)
	for _, t := range tagged {
		d := u.CreatedAt.Sub(t.CreatedAt)
		if d < 0 {
			d = -d
		}
		if d < bestDelta {
			best, bestDelta = t, d
		}
	}
	return best
}

func main() {
	var (
		owner = flag.String("owner", "", "package owner (org); defaults to the owner in GITHUB_REPOSITORY")
		pkg   = flag.String("package", "", "package name, e.g. echo-server")
		keep  = flag.Int("keep", 3, "number of newest releases to keep")
		apply = flag.Bool("apply", false, "delete the versions outside the window (default: dry run)")
		api   = flag.String("api", defaultAPI, "REST API base URL")
		token = flag.String("token", "", "token with packages read/write; defaults to $GH_TOKEN or $GITHUB_TOKEN")
	)
	flag.Parse()

	if *pkg == "" {
		fmt.Fprintln(os.Stderr, "ghcr-prune: -package is required")
		os.Exit(2)
	}
	if *keep < 1 {
		fmt.Fprintln(os.Stderr, "ghcr-prune: -keep must be at least 1")
		os.Exit(2)
	}
	if *owner == "" {
		if i := strings.IndexByte(os.Getenv("GITHUB_REPOSITORY"), '/'); i > 0 {
			*owner = os.Getenv("GITHUB_REPOSITORY")[:i]
		}
	}
	if *owner == "" {
		fmt.Fprintln(os.Stderr, "ghcr-prune: -owner is required (or set GITHUB_REPOSITORY)")
		os.Exit(2)
	}
	if *token == "" {
		*token = os.Getenv("GH_TOKEN")
	}
	if *token == "" {
		*token = os.Getenv("GITHUB_TOKEN")
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "ghcr-prune: no token (set GH_TOKEN or GITHUB_TOKEN)")
		os.Exit(2)
	}

	ctx := context.Background()
	c := client{api: *api, owner: *owner, pkg: *pkg, token: *token, http: &http.Client{Timeout: 30 * time.Second}}
	versions, err := c.listVersions(ctx)
	if err != nil {
		fail(err)
	}
	if len(versions) == 0 {
		fmt.Printf("%s: no versions, nothing to prune\n", *pkg)
		return
	}

	p := decide(versions, *keep)
	fmt.Printf("%s: %d versions, keeping the newest %d releases\n", *pkg, len(versions), *keep)
	for _, r := range p.Keep {
		fmt.Printf("  keep  %s  (+%d fragments)\n", r.Index, len(r.Fragments))
	}
	for _, v := range p.Rescued {
		fmt.Printf("  keep* %s (still the only version tagged with its alias)\n", v)
	}

	toDelete := p.versionsToDelete()
	if len(toDelete) == 0 {
		fmt.Println("nothing to delete")
		return
	}
	for _, v := range toDelete {
		fmt.Printf("  drop  %s\n", v)
	}
	if !*apply {
		fmt.Printf("dry run: %d versions would be deleted (re-run with -apply)\n", len(toDelete))
		return
	}

	var failed int
	for _, v := range toDelete {
		if err := c.deleteVersion(ctx, v.ID); err != nil {
			fmt.Fprintf(os.Stderr, "  %v\n", err)
			failed++
			continue
		}
		fmt.Printf("  deleted %d\n", v.ID)
	}
	if failed > 0 {
		fail(fmt.Errorf("%d of %d deletions failed", failed, len(toDelete)))
	}
	fmt.Printf("%s: deleted %d versions\n", *pkg, len(toDelete))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "ghcr-prune: %v\n", err)
	os.Exit(1)
}
