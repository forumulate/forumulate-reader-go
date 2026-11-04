package reader

// Mirrors packages/reader/test/reader-handoff.test.ts, case for case.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	org   = "07f432f4-34b9-46a7-aaad-c0e395d2e4f9"
	space = "432e77da-6534-4288-88be-688aaf397d79"
)

var endpoints = []Endpoint{
	{
		URL: "https://example.com/docs", Kind: "domain", Primary: true,
		APIBase:      "https://example.com/docs/_api",
		JWTRedeemURL: "https://example.com/docs/_api/public/orgs/" + org + "/spaces/" + space + "/reader-auth/jwt",
		SignOutURL:   "https://example.com/docs/_api/public/reader/sign-out",
	},
	{
		URL: "https://forumulate.com/p/acme/docs", Kind: "platform",
		APIBase:      "https://forumulate.com/api",
		JWTRedeemURL: "https://forumulate.com/api/public/orgs/" + org + "/spaces/" + space + "/reader-auth/jwt",
		SignOutURL:   "https://forumulate.com/api/public/reader/sign-out",
	},
}

type vectorFile struct {
	ExpectedHeaderSegment string `json:"expectedHeaderSegment"`
	Vectors               []struct {
		Name   string `json:"name"`
		Secret string `json:"secret"`
		Now    int64  `json:"now"`
		User   struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			Name          string `json:"name"`
			EmailVerified *bool  `json:"emailVerified"`
			Ext           string `json:"ext"`
			Principal     string `json:"principal"`
		} `json:"user"`
		Options struct {
			Audience string `json:"audience"`
			Issuer   string `json:"issuer"`
			TTLSec   int    `json:"ttlSec"`
		} `json:"options"`
		Payload json.RawMessage `json:"payload"`
	} `json:"vectors"`
}

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("segment %q: %v", s, err)
	}
	return b
}

func verifies(jwt, secret string) bool {
	p := strings.Split(jwt, ".")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(p[0] + "." + p[1]))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) == p[2]
}

func payloadOf(t *testing.T, jwt string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(unb64(t, strings.Split(jwt, ".")[1]), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func newHandoff(t *testing.T, now func() time.Time, mod func(*Options)) *Handoff {
	t.Helper()
	o := Options{OrgID: org, SpaceID: space, SharedSecret: "sek", ReaderEndpoints: endpoints, Now: now}
	if mod != nil {
		mod(&o)
	}
	h, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func at(sec int64) func() time.Time { return func() time.Time { return time.Unix(sec, 0) } }

func TestVectorsMatchTheNodePackage(t *testing.T) {
	ours, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := os.ReadFile("../../packages/reader/test/vectors.json")
	if err != nil {
		t.Skip("outside the monorepo")
	}
	if !bytes.Equal(ours, theirs) {
		t.Fatal("testdata/vectors.json differs from packages/reader/test/vectors.json")
	}
}

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			ms := v.Now
			h := newHandoff(t, func() time.Time { return time.UnixMilli(ms) }, func(o *Options) {
				o.SharedSecret = v.Secret
				o.Audience = v.Options.Audience
				o.Issuer = v.Options.Issuer
				o.TTL = time.Duration(v.Options.TTLSec) * time.Second
			})
			u := v.User
			jwt, err := h.Mint(User{Sub: u.Sub, Email: u.Email, Name: u.Name, EmailVerified: u.EmailVerified, Ext: u.Ext, Principal: u.Principal})
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(jwt, ".")
			if parts[0] != vf.ExpectedHeaderSegment {
				t.Fatalf("header %q", parts[0])
			}
			if string(unb64(t, parts[0])) != `{"alg":"HS256","typ":"JWT"}` {
				t.Fatal("header JSON")
			}
			jti, _ := payloadOf(t, jwt)["jti"].(string)
			if len(unb64(t, jti)) != 16 {
				t.Fatalf("jti %q", jti)
			}
			// json.Compact keeps key order and string bytes as written, so this is
			// the exact payload JSON.stringify writes, with the random jti appended.
			var want bytes.Buffer
			if err := json.Compact(&want, v.Payload); err != nil {
				t.Fatal(err)
			}
			expected := strings.TrimSuffix(want.String(), "}") + `,"jti":` + jsonString(jti) + "}"
			if got := string(unb64(t, parts[1])); got != expected {
				t.Fatalf("payload\n got %s\nwant %s", got, expected)
			}
			if !verifies(jwt, v.Secret) || verifies(jwt, v.Secret+"x") {
				t.Fatal("signature")
			}
		})
	}
}

func TestJSONStringMatchesJSONStringify(t *testing.T) {
	cases := map[string]string{
		"a<b>&c":       `"a<b>&c"`,
		"line sep":     "\"line sep\"",
		"q\"\\/":       `"q\"\\/"`,
		"\n\t\x01\x7f": `"\n\t\u0001` + "\x7f\"",
		"ü😀":           `"ü😀"`,
	}
	for in, want := range cases {
		if got := jsonString(in); got != want {
			t.Errorf("jsonString(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestFreshTokenPerCall(t *testing.T) {
	sec := int64(1_793_000_000)
	h := newHandoff(t, func() time.Time { return time.Unix(sec, 0) }, nil)
	a, _ := h.Mint(User{Sub: "u", Email: "u@example.com"})
	sec += 61
	b, _ := h.Mint(User{Sub: "u", Email: "u@example.com"})
	pa, pb := payloadOf(t, a), payloadOf(t, b)
	if pa["jti"] == pb["jti"] {
		t.Fatal("jti repeated")
	}
	if pb["iat"].(float64)-pa["iat"].(float64) != 61 || pb["exp"].(float64)-pb["iat"].(float64) != 120 {
		t.Fatal("iat/exp")
	}
}

func TestCapsLifetimeAt300(t *testing.T) {
	jwt, _ := newHandoff(t, at(0), func(o *Options) { o.TTL = 10_000 * time.Second }).Mint(User{Sub: "u", Email: "e@x.io"})
	p := payloadOf(t, jwt)
	if p["exp"].(float64)-p["iat"].(float64) != 300 {
		t.Fatal("not capped")
	}
}

func TestRedeemURLOnTheServingHost(t *testing.T) {
	ctx := context.Background()
	h := newHandoff(t, time.Now, nil)
	link, err := h.RedeemURL(ctx, RedeemInput{User: User{Sub: "u", Email: "e@x.io"}, ReturnTo: "https://example.com/docs/a?b=1"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	if u.Scheme+"://"+u.Host+u.Path != endpoints[0].JWTRedeemURL {
		t.Fatalf("redeem at %s", link)
	}
	if u.Query().Get("returnTo") != "https://example.com/docs/a?b=1" || !verifies(u.Query().Get("jwt"), "sek") {
		t.Fatal("query")
	}
	if !strings.Contains(link, "returnTo=https%3A%2F%2Fexample.com%2Fdocs%2Fa%3Fb%3D1") {
		t.Fatal("not encodeURIComponent-encoded")
	}
	body, err := h.RedeemBody(ctx, RedeemInput{User: User{Sub: "u", Email: "e@x.io"}, ReturnTo: "https://forumulate.com/p/acme/docs/x"})
	if err != nil || body.URL != endpoints[1].JWTRedeemURL || body.Body.ReturnTo != "https://forumulate.com/p/acme/docs/x" {
		t.Fatalf("body %+v %v", body, err)
	}
}

func TestRefusesWithoutSubOrEmail(t *testing.T) {
	h := newHandoff(t, at(0), nil)
	if _, err := h.Mint(User{Email: "e@x.io"}); err == nil || !strings.Contains(err.Error(), "Sub") {
		t.Fatal(err)
	}
	if _, err := h.Mint(User{Sub: "u"}); err == nil || !strings.Contains(err.Error(), "Email") {
		t.Fatal(err)
	}
	if _, err := New(Options{SharedSecret: "s"}); err == nil {
		t.Fatal("OrgID")
	}
	if _, err := New(Options{OrgID: org}); err == nil {
		t.Fatal("SharedSecret")
	}
}

func TestSignOutCookies(t *testing.T) {
	h := newHandoff(t, at(0), nil)
	lines := h.SignOutCookies(space, "other", space)
	want := []string{"forumulate_session", "fm_signed_in", "cflx_vis_org_" + org, "cflx_vis_" + space, "cflx_vis_other"}
	if len(lines) != len(want) {
		t.Fatalf("%d lines", len(lines))
	}
	for i, l := range lines {
		if strings.SplitN(l, "=", 2)[0] != want[i] {
			t.Fatalf("line %d: %s", i, l)
		}
		for _, part := range []string{"Path=/", "Max-Age=0", "Secure", "HttpOnly", "SameSite=Lax"} {
			if !strings.Contains(l, part) {
				t.Fatalf("%s lacks %s", l, part)
			}
		}
		if strings.Contains(strings.ToLower(l), "domain=") {
			t.Fatal("not host-only")
		}
	}
	if len(h.SignOutCookies()) != 4 || len(h.SignOutCookies([]string{}...)) != 3 {
		t.Fatal("default space handling")
	}
}

func TestSignOutURL(t *testing.T) {
	ctx := context.Background()
	h := newHandoff(t, at(0), nil)
	if s, _ := h.SignOutURL(ctx, "", ""); s != endpoints[0].SignOutURL {
		t.Fatal(s)
	}
	if s, _ := h.SignOutURL(ctx, "https://forumulate.com/p/acme/docs/x", ""); s != endpoints[1].SignOutURL {
		t.Fatal(s)
	}
}

func endpointServer(t *testing.T, status *atomic.Int32, calls *atomic.Int32, path *atomic.Value) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		path.Store(r.URL.Path + " " + r.Header.Get("Authorization"))
		w.WriteHeader(int(status.Load()))
		_ = json.NewEncoder(w).Encode(map[string]any{"readerEndpoints": endpoints})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCachesEndpointsForTenMinutes(t *testing.T) {
	var status, calls atomic.Int32
	var path atomic.Value
	status.Store(200)
	srv := endpointServer(t, &status, &calls, &path)
	now := time.Unix(0, 0)
	h := newHandoff(t, func() time.Time { return now }, func(o *Options) {
		o.ReaderEndpoints, o.AdminToken, o.APIBase, o.HTTPClient = nil, "tok", srv.URL+"/api/", srv.Client()
	})
	ctx := context.Background()
	_, _ = h.Endpoints(ctx, "")
	if _, err := h.Endpoints(ctx, ""); err != nil || calls.Load() != 1 {
		t.Fatalf("calls %d, %v", calls.Load(), err)
	}
	if p := path.Load().(string); p != "/api/orgs/"+org+"/spaces/"+space+"/reader-auth Bearer tok" {
		t.Fatal(p)
	}
	now = now.Add(EndpointsTTL + time.Second)
	_, _ = h.Endpoints(ctx, "")
	if calls.Load() != 2 {
		t.Fatal("not refreshed")
	}
}

func TestKeepsStaleListWhenRefreshFails(t *testing.T) {
	var status, calls atomic.Int32
	var path atomic.Value
	status.Store(200)
	srv := endpointServer(t, &status, &calls, &path)
	now := time.Unix(0, 0)
	h := newHandoff(t, func() time.Time { return now }, func(o *Options) {
		o.ReaderEndpoints, o.AdminToken, o.APIBase, o.HTTPClient = nil, "tok", srv.URL, srv.Client()
	})
	ctx := context.Background()
	_, _ = h.Endpoints(ctx, "")
	status.Store(503)
	now = now.Add(EndpointsTTL + time.Second)
	eps, err := h.Endpoints(ctx, "")
	if err != nil || len(eps) != 2 || eps[0].URL != endpoints[0].URL {
		t.Fatalf("%v %v", eps, err)
	}
	h2 := newHandoff(t, at(0), func(o *Options) {
		o.ReaderEndpoints, o.AdminToken, o.APIBase, o.HTTPClient = nil, "tok", srv.URL, srv.Client()
	})
	if _, err := h2.Endpoints(ctx, ""); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatal(err)
	}
}

func TestNeedsEndpointsFromSomewhere(t *testing.T) {
	h := newHandoff(t, at(0), func(o *Options) { o.ReaderEndpoints = nil })
	if _, err := h.Endpoints(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "ReaderEndpoints") {
		t.Fatal(err)
	}
}

func TestValidateReturnToAccepts(t *testing.T) {
	for _, v := range []string{"https://example.com/docs/guide#x", "https://example.com/docs", "https://EXAMPLE.com:443/docs/a"} {
		if e, err := ValidateReturnTo(v, endpoints); err != nil || e.Kind != "domain" {
			t.Fatalf("%s: %v", v, err)
		}
	}
}

func TestValidateReturnToRefuses(t *testing.T) {
	cases := []struct{ value, why string }{
		{"http://example.com/docs/a", "https"},
		{"https://evil.com/docs/a", "not under"},
		{"https://example.com/docsx/a", "not under"},
		{"https://example.com/other", "not under"},
		{"https://example.com/docs/../other", "not under"},
		{"https://example.com/docs/%2e%2E/other", "not under"},
		{"https://example.com:8443/docs/a", "not under"},
		{"https://user:pw@example.com/docs/a", "credentials"},
		{"/docs/a", "absolute"},
		{`https://example.com\@evil.com/docs`, "backslash"},
		{"https://example.com/docs/" + strings.Repeat("a", 2048), "2048"},
		{"", "required"},
	}
	for _, c := range cases {
		_, err := ValidateReturnTo(c.value, endpoints)
		var rt *ReturnToError
		if !errors.As(err, &rt) || !regexp.MustCompile(c.why).MatchString(rt.Message) {
			t.Errorf("%.60s: %v", c.value, err)
		}
	}
}

func TestMapError(t *testing.T) {
	for _, r := range append(append([]string{}, ExternalJWTReasons...), IdPReasons...) {
		if ReasonHints[r] == "" {
			t.Errorf("no hint for %s", r)
		}
	}
	for _, r := range []string{"jwks_unreachable", "jwks_unavailable", "discovery_failed", "expired", "iat_too_old"} {
		if !MapError([]byte(`{"error":{"code":"auth.token_invalid","message":"x","reason":"` + r + `"}}`)).Retry {
			t.Errorf("%s should retry", r)
		}
	}
	for _, r := range []string{"wrong_audience", "bad_audience", "unknown_issuer", "bad_signature", "missing_email", "not_configured"} {
		if MapReason(r).Retry {
			t.Errorf("%s should be final", r)
		}
	}
	if !strings.Contains(MapReason("bad_audience").Hint, "aud") || !strings.Contains(MapReason("wrong_audience").Hint, "aud") {
		t.Error("audience hints")
	}
	if m := MapError([]byte(`{"error":{"reason":"brand_new"}}`)); m.Reason != "brand_new" || m.Retry {
		t.Error(m)
	}
	for _, b := range []string{`{}`, `null`, `not json`, `{"error":{"reason":7}}`} {
		if MapError([]byte(b)).Reason != "unknown" {
			t.Errorf("%s should be unknown", b)
		}
	}
}
