# forumulate-reader-go

Sign the users of your app in to your Forumulate docs, forum and blog, using
the `external_jwt` reader sign-in method. This is the Go port of
[`@forumulate/reader`](https://forumulate.com/guides/reader-sign-in-with-your-app):
same claims, same rules, same test vectors. Standard library only, Go 1.21+.

> If your app already signs users in with an OpenID Connect provider (Atlas,
> Auth0, Clerk, Okta, Cognito, Keycloak, Entra, Firebase, Supabase, WorkOS or
> any other), you may not need this module at all. Configure that provider as a
> reader sign-in method and hand us its own token. See
> [Reader sign-in with your app](https://forumulate.com/guides/reader-sign-in-with-your-app).

```sh
go get github.com/forumulate/forumulate-reader-go
```

## Hand-off

```go
import reader "github.com/forumulate/forumulate-reader-go"

handoff, err := reader.New(reader.Options{
	OrgID:        os.Getenv("FORUMULATE_ORG_ID"),
	SpaceID:      os.Getenv("FORUMULATE_SPACE_ID"),
	SharedSecret: os.Getenv("FORUMULATE_READER_SECRET"),    // the external_jwt sharedSecret
	Audience:     os.Getenv("FORUMULATE_READER_CLIENT_ID"), // only if the provider has a clientId
	Issuer:       "https://app.example.com",                // only if the provider has an issuer
	// Either copy readerEndpoints from GET /orgs/{org}/spaces/{space}/reader-auth ...
	// ReaderEndpoints: []reader.Endpoint{...},
	// ... or let the helper read (and cache for 10 minutes) them with an admin token:
	AdminToken: os.Getenv("FORUMULATE_ADMIN_TOKEN"),
})
if err != nil {
	log.Fatal(err)
}
```

### net/http

```go
http.HandleFunc("/docs-sign-in", func(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r) // your session
	returnTo := r.URL.Query().Get("returnTo")
	if returnTo == "" {
		returnTo = "https://example.com/docs"
	}
	link, err := handoff.RedeemURL(r.Context(), reader.RedeemInput{
		User:     reader.User{Sub: u.ID, Email: u.Email, Name: u.Name},
		ReturnTo: returnTo,
	})
	var bad *reader.ReturnToError
	if errors.As(err, &bad) {
		http.Error(w, bad.Message, http.StatusBadRequest)
		return
	} else if err != nil {
		http.Error(w, "docs sign-in unavailable", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, link, http.StatusFound)
})
```

Rules the helper keeps for you:

- **A fresh token per call.** `iat` is now, `exp` is 120 s later (never more
  than 300 s: the server refuses an `iat` older than that). Never cache one.
  `Options.TTL` changes the lifetime within that cap.
- **HS256, keyed with the UTF-8 bytes of the secret**, not a base64 decode.
- **The reader's own host.** The cookies are host-only, so the token is
  redeemed at the address the page is served from (`<mount>/_api/...` on your
  domain), picked from `readerEndpoints` by `ReturnTo`.
- **`ReturnTo` is checked first:** absolute `https`, no credentials, no
  backslashes or whitespace, at most 2048 characters, and under one of the
  space's addresses after `.`/`..` segments are resolved. A bad value is a
  `*ReturnToError` instead of a reader silently landing on the space root.
- **`Sub` is the key, not the email.** A user who changes address comes back
  as the same reader. `EmailVerified` is a `*bool` that defaults to true
  (`reader.Bool(false)` to send false).

`RedeemBody()` answers the URL and `{jwt, returnTo}` body for a server-side
POST instead of a link; `Mint()` answers a bare token. A `Handoff` is safe for
concurrent use.

## Sign-out, both ways

- From your app on the **same host** as the docs: add each of
  `handoff.SignOutCookies()` as a `Set-Cookie` header.
- From **anywhere else**: POST to `handoff.SignOutURL(ctx, returnTo, "")`; it
  revokes the session and clears the cookies on the reader's host.
- From Forumulate to you: set `signOutUrl` on the reader-auth registry and we
  send the reader there after ours.

```go
for _, line := range handoff.SignOutCookies() {
	w.Header().Add("Set-Cookie", line)
}
```

## Errors

```go
res, err := http.Post(body.URL, "application/json", bytes.NewReader(payload))
// ...
if res.StatusCode >= 400 {
	raw, _ := io.ReadAll(res.Body)
	advice := reader.MapError(raw) // or reader.MapReason("expired")
	if advice.Retry {
		// mint a fresh token and try once more
	}
}
```

`MapError` knows every `error.reason` the redeem endpoint sends (both the
`external_jwt` and identity-provider families); the table is in the guide.
Configuration mistakes are a `*reader.Error`.

## Tests

```sh
go test ./...
```

`testdata/vectors.json` is the same file as the Node package's
`test/vectors.json` (a test asserts it, inside the monorepo). It pins the header
segment, the payload JSON byte for byte (key order included) and the signature.

## License

MIT

---

## About this repository

This repository is a public mirror, refreshed on each Forumulate release
(one commit per release). Pull requests are welcome; accepted changes are
applied upstream and arrive here with the next release.

- API reference: https://forumulate.com/reference
- Guides: https://forumulate.com/guides
- Community and support: https://forumulate.com/community
- Source: https://github.com/forumulate/forumulate-reader-go
