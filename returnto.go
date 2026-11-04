package reader

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"
)

// Where a reader may be sent after sign-in.
//
// The server re-validates returnTo against the space's addresses and falls
// back to the space root when it refuses one. A bad value therefore never
// becomes an open redirect, but it does become a reader who lands somewhere they
// did not ask for. Checking it here first turns that into an error the
// integrator sees.
//
// net/url is not a WHATWG URL parser, so what the Node helper gets from
// new URL() is done by hand: the host is lowercased and the default port
// dropped (the origin comparison), and "." / ".." segments (also spelled %2e)
// are resolved before the path is compared. Without that last step
// https://example.com/docs/../admin would look as if it were under /docs.
// Backslashes, whitespace and control characters are refused outright: a
// browser reads "\" as "/" in an https URL, so the string we checked would not
// be the address the reader is sent to.

// ReturnToMax is the same cap as the server's READER_RETURN_TO_MAX, in UTF-16 code units.
const ReturnToMax = 2048

// Endpoint is one address a space is served at, as
// GET /orgs/{org}/spaces/{space}/reader-auth reports it in readerEndpoints.
type Endpoint struct {
	URL          string `json:"url"`
	Kind         string `json:"kind"` // platform | site | domain
	Primary      bool   `json:"primary"`
	APIBase      string `json:"apiBase"`
	JWTRedeemURL string `json:"jwtRedeemUrl"`
	SignOutURL   string `json:"signOutUrl"`
}

func removeDotSegments(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	out := make([]string, 0, len(segments))
	for i, seg := range segments {
		if i == 0 {
			continue // the empty segment before the leading "/"
		}
		norm := strings.ReplaceAll(strings.ToLower(seg), "%2e", ".")
		last := i == len(segments)-1
		switch norm {
		case ".":
			if last {
				out = append(out, "")
			}
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, seg)
		}
	}
	return "/" + strings.Join(out, "/")
}

// originAndPath answers the origin and normalized path of an absolute https URL.
func originAndPath(u *url.URL) (string, string, bool) {
	host := strings.ToLower(u.Hostname())
	if strings.ToLower(u.Scheme) != "https" || host == "" {
		return "", "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	origin := "https://" + host
	if p := u.Port(); p != "" && p != "443" {
		origin += ":" + p
	}
	return origin, removeDotSegments(u.EscapedPath()), true
}

// under is true when the URL is root itself or a path under it (not merely a string prefix).
func under(origin, path, root string) bool {
	r, err := url.Parse(root)
	if err != nil {
		return false
	}
	ro, rp, ok := originAndPath(r)
	if !ok || ro != origin {
		return false
	}
	base := strings.TrimRight(rp, "/")
	return base == "" || path == base || strings.HasPrefix(path, base+"/")
}

func rte(format string, a ...any) error { return &ReturnToError{Message: fmt.Sprintf(format, a...)} }

// ValidateReturnTo validates returnTo and answers the endpoint it belongs to.
// It returns a *ReturnToError when returnTo is not an absolute https URL under
// one of the space's reader addresses.
func ValidateReturnTo(returnTo string, endpoints []Endpoint) (Endpoint, error) {
	if returnTo == "" {
		return Endpoint{}, rte("returnTo is required.")
	}
	if len(utf16.Encode([]rune(returnTo))) > ReturnToMax {
		return Endpoint{}, rte("returnTo is longer than %d characters.", ReturnToMax)
	}
	if strings.ContainsFunc(returnTo, func(r rune) bool {
		return r == '\\' || unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return Endpoint{}, rte("returnTo must not contain backslashes, whitespace or control characters.")
	}
	u, err := url.Parse(returnTo)
	if err != nil || u.Scheme == "" {
		return Endpoint{}, rte("returnTo must be an absolute URL.")
	}
	if strings.ToLower(u.Scheme) != "https" {
		return Endpoint{}, rte("returnTo must be https.")
	}
	if u.Host == "" {
		return Endpoint{}, rte("returnTo must be an absolute URL.")
	}
	if u.User != nil {
		return Endpoint{}, rte("returnTo must not carry credentials.")
	}
	origin, path, _ := originAndPath(u)
	// Longest root first, so a custom-domain mount wins over a bare host.
	sorted := append([]Endpoint(nil), endpoints...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i].URL) > len(sorted[j].URL) })
	for _, e := range sorted {
		if under(origin, path, e.URL) {
			return e, nil
		}
	}
	urls := make([]string, len(endpoints))
	for i, e := range endpoints {
		urls[i] = e.URL
	}
	known := strings.Join(urls, ", ")
	if known == "" {
		known = "none known"
	}
	return Endpoint{}, rte("returnTo is not under any address of this space (%s).", known)
}

// PrimaryEndpoint is the endpoint readers go to by default: the primary, else
// the first. ok is false when there are none.
func PrimaryEndpoint(endpoints []Endpoint) (Endpoint, bool) {
	for _, e := range endpoints {
		if e.Primary {
			return e, true
		}
	}
	if len(endpoints) > 0 {
		return endpoints[0], true
	}
	return Endpoint{}, false
}
