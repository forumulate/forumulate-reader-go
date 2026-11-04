// Package reader signs your app's users in to your Forumulate docs, forum and
// blog with the external_jwt reader sign-in method: a hand-off link, sign-out
// cookies and error.reason mapping. It is a standard-library port of
// @forumulate/reader; testdata/vectors.json is the conformance input both share.
//
// Every call mints a FRESH token, because the server refuses one whose iat is
// more than 300 s old. A token cached at login stops working five minutes
// later, and that is the failure integrators hit most. The token goes to the
// redeem URL on the reader's OWN host (<mount>/_api/…), because the cookies it
// sets are host-only. Redeeming on forumulate.com signs the reader in on
// forumulate.com and nowhere else.
package reader

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// EndpointsTTL is how long a fetched readerEndpoints list is trusted before it is read again.
const EndpointsTTL = 10 * time.Minute

// DefaultAPIBase is where the admin read of readerEndpoints goes by default.
const DefaultAPIBase = "https://forumulate.com/api"

// Options configures a Handoff. OrgID and SharedSecret are required.
type Options struct {
	OrgID string
	// SpaceID is the space readers usually start on; a call may name another.
	SpaceID string
	// SharedSecret is the external_jwt provider's sharedSecret. Server-side only.
	SharedSecret string
	// Issuer goes in iss when set; it must match the provider's issuer, if it has one.
	Issuer string
	// Audience goes in aud; it must equal the provider's clientId, when it has one.
	Audience string
	// ClientID is an alias for Audience, named as the provider config names it.
	ClientID string
	// APIBase defaults to https://forumulate.com/api.
	APIBase string
	// AdminToken is an admin API token used ONLY to read the space's
	// readerEndpoints (GET /orgs/{org}/spaces/{space}/reader-auth). Without one,
	// pass ReaderEndpoints (copy them from that response).
	AdminToken      string
	ReaderEndpoints []Endpoint
	// TTL is the token lifetime: zero means 120 s; it is floored to whole
	// seconds, at least 1 s and capped at 300 s (the server's limit).
	TTL time.Duration
	// HTTPClient defaults to a client with a 10 s timeout.
	HTTPClient *http.Client
	// Now is the clock, for tests. Defaults to time.Now.
	Now func() time.Time
}

// User is the signed-in user of your app.
type User struct {
	// Sub is your stable user id. The reader's key here, never the email.
	Sub   string
	Email string
	Name  string
	// EmailVerified defaults to true when nil.
	EmailVerified *bool
	// Ext is your own account id (merchant:<uuid>), stored as an attribute.
	Ext string
	// Principal is the role the user is acting as right now (merchant, partner).
	Principal string
}

// RedeemInput names who to sign in and where they land.
type RedeemInput struct {
	User User
	// ReturnTo is the absolute page address to land on after sign-in.
	ReturnTo string
	// SpaceID overrides Options.SpaceID for this call.
	SpaceID string
}

// RedeemBody is what a server-side POST sends to URL.
type RedeemBody struct {
	URL  string
	Body struct {
		JWT      string `json:"jwt"`
		ReturnTo string `json:"returnTo"`
	}
}

type cached struct {
	at        time.Time
	endpoints []Endpoint
}

// Handoff mints hand-off tokens and builds redeem and sign-out addresses for
// one org. It is safe for concurrent use.
type Handoff struct {
	opts  Options
	mu    sync.Mutex
	cache map[string]cached
}

func herr(format string, a ...any) error { return &Error{Message: fmt.Sprintf(format, a...)} }

// New validates opts and answers a Handoff.
func New(opts Options) (*Handoff, error) {
	if opts.OrgID == "" {
		return nil, herr("reader: OrgID is required.")
	}
	if opts.SharedSecret == "" {
		return nil, herr("reader: SharedSecret is required.")
	}
	return &Handoff{opts: opts, cache: map[string]cached{}}, nil
}

// Bool is a helper for User.EmailVerified.
func Bool(v bool) *bool { return &v }

func (h *Handoff) now() time.Time {
	if h.opts.Now != nil {
		return h.opts.Now()
	}
	return time.Now()
}

func (h *Handoff) spaceOf(spaceID string) (string, error) {
	if spaceID == "" {
		spaceID = h.opts.SpaceID
	}
	if spaceID == "" {
		return "", herr("reader: SpaceID is required (on the call or in Options).")
	}
	return spaceID, nil
}

func copyEndpoints(e []Endpoint) []Endpoint { return append([]Endpoint(nil), e...) }

// Endpoints answers the space's reader addresses, from Options or a cached
// admin read. spaceID "" means Options.SpaceID.
func (h *Handoff) Endpoints(ctx context.Context, spaceID string) ([]Endpoint, error) {
	id, err := h.spaceOf(spaceID)
	if err != nil {
		return nil, err
	}
	if h.opts.AdminToken == "" {
		if len(h.opts.ReaderEndpoints) > 0 {
			return copyEndpoints(h.opts.ReaderEndpoints), nil
		}
		return nil, herr("reader: pass ReaderEndpoints, or an AdminToken to read them.")
	}
	h.mu.Lock()
	hit, have := h.cache[id]
	h.mu.Unlock()
	if have && h.now().Sub(hit.at) < EndpointsTTL {
		return copyEndpoints(hit.endpoints), nil
	}
	base := strings.TrimRight(h.opts.APIBase, "/")
	if base == "" {
		base = DefaultAPIBase
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/orgs/"+url.PathEscape(h.opts.OrgID)+"/spaces/"+url.PathEscape(id)+"/reader-auth", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.opts.AdminToken)
	req.Header.Set("Accept", "application/json")
	client := h.opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		// A stale list beats none: the addresses of a space rarely change.
		if have {
			return copyEndpoints(hit.endpoints), nil
		}
		return nil, herr("reader: reading readerEndpoints failed (%d).", res.StatusCode)
	}
	var body struct {
		ReaderEndpoints []Endpoint `json:"readerEndpoints"`
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &body) != nil || len(body.ReaderEndpoints) == 0 {
		return nil, herr("reader: the space reported no reader addresses.")
	}
	h.mu.Lock()
	h.cache[id] = cached{at: h.now(), endpoints: body.ReaderEndpoints}
	h.mu.Unlock()
	return copyEndpoints(body.ReaderEndpoints), nil
}

// Mint answers a freshly minted token for user. Exposed for callers that POST it themselves.
func (h *Handoff) Mint(user User) (string, error) {
	if user.Sub == "" {
		return "", herr("reader: user.Sub is required.")
	}
	if user.Email == "" {
		return "", herr("reader: user.Email is required.")
	}
	iat := h.now().Unix()
	ttl := int64(DefaultTTLSec)
	if h.opts.TTL != 0 {
		ttl = int64(h.opts.TTL / time.Second)
	}
	if ttl < 1 {
		ttl = 1
	}
	if ttl > MaxTTLSec {
		ttl = MaxTTLSec
	}
	aud := h.opts.Audience
	if aud == "" {
		aud = h.opts.ClientID
	}
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	// The slice order IS the wire order: the vectors pin it byte for byte.
	claims := []claim{{"sub", user.Sub}, {"email", user.Email}}
	if user.Name != "" {
		claims = append(claims, claim{"name", user.Name})
	}
	claims = append(claims, claim{"email_verified", user.EmailVerified == nil || *user.EmailVerified})
	if aud != "" {
		claims = append(claims, claim{"aud", aud})
	}
	if h.opts.Issuer != "" {
		claims = append(claims, claim{"iss", h.opts.Issuer})
	}
	if user.Ext != "" {
		claims = append(claims, claim{"ext", user.Ext})
	}
	if user.Principal != "" {
		claims = append(claims, claim{"principal", user.Principal})
	}
	claims = append(claims, claim{"iat", iat}, claim{"exp", iat + ttl}, claim{"jti", jti})
	return signClaims(claims, h.opts.SharedSecret), nil
}

// RedeemBody answers the URL and JSON body for a server-side POST (it answers
// JSON and sets the cookies on that host).
func (h *Handoff) RedeemBody(ctx context.Context, in RedeemInput) (RedeemBody, error) {
	var out RedeemBody
	eps, err := h.Endpoints(ctx, in.SpaceID)
	if err != nil {
		return out, err
	}
	endpoint, err := ValidateReturnTo(in.ReturnTo, eps)
	if err != nil {
		return out, err
	}
	jwt, err := h.Mint(in.User)
	if err != nil {
		return out, err
	}
	out.URL = endpoint.JWTRedeemURL
	out.Body.JWT = jwt
	out.Body.ReturnTo = in.ReturnTo
	return out, nil
}

// RedeemURL answers a link to redirect the browser to: it lands signed in on ReturnTo.
func (h *Handoff) RedeemURL(ctx context.Context, in RedeemInput) (string, error) {
	r, err := h.RedeemBody(ctx, in)
	if err != nil {
		return "", err
	}
	return r.URL + "?jwt=" + encodeURIComponent(r.Body.JWT) + "&returnTo=" + encodeURIComponent(r.Body.ReturnTo), nil
}

// SignOutCookies answers Set-Cookie values expiring every reader cookie, for a
// sign-out answered on the SAME host the docs are served from; otherwise use
// SignOutURL. With no arguments it covers Options.SpaceID; pass an empty,
// non-nil slice (SignOutCookies([]string{}...)) for the org cookies only.
func (h *Handoff) SignOutCookies(spaceIDs ...string) []string {
	if spaceIDs == nil && h.opts.SpaceID != "" {
		spaceIDs = []string{h.opts.SpaceID}
	}
	names := ReaderCookieNames(h.opts.OrgID, spaceIDs...)
	lines := make([]string, len(names))
	for i, n := range names {
		lines[i] = ExpireCookie(n)
	}
	return lines
}

// SignOutURL answers the reader sign-out address on the reader's host (a POST
// there revokes the session and clears every reader cookie). With returnTo,
// the endpoint serving that page is used; with "", the primary.
func (h *Handoff) SignOutURL(ctx context.Context, returnTo, spaceID string) (string, error) {
	eps, err := h.Endpoints(ctx, spaceID)
	if err != nil {
		return "", err
	}
	if returnTo != "" {
		e, err := ValidateReturnTo(returnTo, eps)
		if err != nil {
			return "", err
		}
		return e.SignOutURL, nil
	}
	e, ok := PrimaryEndpoint(eps)
	if !ok {
		return "", herr("reader: the space reported no reader addresses.")
	}
	return e.SignOutURL, nil
}

// encodeURIComponent escapes s exactly as JavaScript's encodeURIComponent, so
// the link matches the Node helper's (url.QueryEscape writes "+" for a space
// and escapes !'()*).
func encodeURIComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xF])
	}
	return b.String()
}
