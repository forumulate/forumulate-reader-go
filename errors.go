package reader

import "encoding/json"

// error.reason to what to do about it.
//
// A refused redeem answers 401 {error:{code, message, reason}}. The reason is a
// stable word (adding one is fine, renaming one is a breaking change on the
// server), so integrations branch on it rather than on English. Two families
// share this map: the external_jwt words, and the identity-provider words
// (wrong_audience, unknown_issuer, ...). Where both spellings exist for one
// problem (bad_audience / wrong_audience) both are listed with the same advice.
//
// Kept identical to @forumulate/reader (src/errors.ts); the tests pin both
// families.

// Error is a misconfigured hand-off, or a failed read of the space's reader addresses.
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

// ReturnToError means returnTo is not an absolute https URL under one of the
// space's reader addresses. Test for it with errors.As.
type ReturnToError struct{ Message string }

func (e *ReturnToError) Error() string { return e.Message }

// MappedError is the advice for one error.reason.
type MappedError struct {
	// Reason is the server's error.reason, or "unknown" when it sent none.
	Reason string
	// Hint is one sentence an integrator can act on.
	Hint string
	// Retry is true when sending a FRESH token (or simply retrying) can succeed.
	Retry bool
}

// ExternalJWTReasons are the error.reason words of the external_jwt method.
var ExternalJWTReasons = []string{
	"malformed", "bad_signature", "bad_algorithm", "unknown_key", "jwks_unavailable",
	"bad_issuer", "bad_audience", "expired", "not_yet_valid", "iat_too_old",
	"iat_in_future", "missing_claim", "invalid_claim", "missing_email", "not_configured",
}

// IdPReasons are the error.reason words of the identity-provider methods.
var IdPReasons = []string{
	"wrong_audience", "unknown_issuer", "expired", "bad_signature", "jwks_unreachable",
	"lifetime_too_long", "not_yet_valid", "wrong_token_use", "bad_algorithm", "unknown_key",
	"missing_claim", "malformed", "discovery_failed", "not_configured",
}

// ReasonHints maps every known reason to its advice.
var ReasonHints = map[string]string{
	"malformed":         "That is not a JWT: three base64url segments separated by dots.",
	"bad_signature":     "The signature did not verify. For external_jwt the HS256 key is the UTF-8 bytes of the shared secret; for an IdP token, is it from the configured instance?",
	"bad_algorithm":     "external_jwt with a shared secret accepts HS256 only; IdP tokens accept asymmetric algorithms only (RS*, PS*, ES*, EdDSA).",
	"unknown_key":       "No key in the JWKS matches the token kid, even after a refetch. Publish the key, or check the kid.",
	"jwks_unavailable":  "Forumulate could not fetch your jwksUrl. Retry; if it persists, check that the URL answers publicly.",
	"jwks_unreachable":  "Forumulate could not fetch the issuer keys. Retry; if it persists, check the jwks_uri the discovery document names.",
	"bad_issuer":        "The iss claim does not match the issuer configured on the provider.",
	"bad_audience":      "The aud claim does not match the configured clientId / audience.",
	"wrong_audience":    "The token was minted for someone else. Mint it with aud = forumulate:<orgId> (or the audience configured on the provider).",
	"unknown_issuer":    "No reader sign-in provider on this space has that issuer. Check the provider config, or the iss your IdP puts in its tokens.",
	"expired":           "The token has expired. Mint a fresh one per redirect; never cache a reader token.",
	"not_yet_valid":     "The token is not valid yet (nbf/iat in the future). Check the clock of the server that minted it.",
	"iat_too_old":       "iat is more than 300 seconds old. Mint the token at the moment you redirect, not ahead of time.",
	"iat_in_future":     "iat is ahead of Forumulate's clock by more than 30 seconds. Sync the minting server's clock (NTP).",
	"missing_claim":     "A required claim is missing: sub, exp and iat are required.",
	"invalid_claim":     "A claim has the wrong type or value. Check sub/exp/iat are present and well-formed.",
	"missing_email":     "The token needs an email claim to create the reader's account.",
	"not_configured":    "This space has no reader sign-in provider that accepts tokens (external_jwt with a sharedSecret or jwksUrl, or an IdP preset).",
	"lifetime_too_long": "The token lives longer than this provider allows. Shorten its lifetime (Atlas: 120 s).",
	"wrong_token_use":   "The token is not the kind this provider accepts (token_use).",
	"discovery_failed":  "The issuer discovery document could not be read or names a different issuer. Retry; then check the issuer URL.",
}

// retryable are the reasons where a retry, or a freshly minted token, can succeed.
var retryable = map[string]bool{
	"jwks_unreachable": true, "jwks_unavailable": true, "discovery_failed": true, "expired": true, "iat_too_old": true,
}

const unknownHint = "Forumulate refused the hand-off without a reason this helper knows. Read error.message and error.docs."

// MapReason maps a bare error.reason to advice.
func MapReason(reason string) MappedError {
	hint, ok := ReasonHints[reason]
	if reason == "" || !ok {
		if reason == "" {
			reason = "unknown"
		}
		return MappedError{Reason: reason, Hint: unknownHint}
	}
	return MappedError{Reason: reason, Hint: hint, Retry: retryable[reason]}
}

// MapError maps a Forumulate error response body ({"error":{"reason":…}}) to
// advice. A body that is not JSON, or names no reason, maps to "unknown".
func MapError(body []byte) MappedError {
	var parsed struct {
		Error struct {
			Reason any `json:"reason"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return MapReason("")
	}
	reason, _ := parsed.Error.Reason.(string)
	return MapReason(reason)
}
