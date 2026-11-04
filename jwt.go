package reader

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A minimal HS256 signer: the one algorithm external_jwt accepts with a
// shared secret. Standard library only, because a JWT library would be the only
// thing this module pulls in.
//
// The key is the UTF-8 bytes of the secret string, exactly as the server reads
// it, NOT a base64 decode of it. Decoding it is the most common reason a
// hand-written integration gets bad_signature.
//
// The payload JSON is written by hand rather than with encoding/json, because
// encoding/json escapes <, >, & and U+2028/U+2029 where JSON.stringify does
// not. The Node helper and this one must write the same bytes; the shared
// vectors.json pins that.

const (
	// DefaultTTLSec is the token lifetime when Options.TTL is zero.
	DefaultTTLSec = 120
	// MaxTTLSec is the most the server accepts: it refuses an iat older than this.
	MaxTTLSec = 300
)

// claim is one payload member; the slice order is the wire order.
type claim struct {
	key   string
	value any // string, bool or int64
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jsonString quotes s the way JSON.stringify does.
func jsonString(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				const hex = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hex[r>>4])
				b.WriteByte(hex[r&0xF])
			} else {
				var buf [utf8.UTFMax]byte
				n := utf8.EncodeRune(buf[:], r)
				b.Write(buf[:n])
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func encodeClaims(claims []claim) string {
	var b strings.Builder
	b.WriteByte('{')
	for i, c := range claims {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(c.key))
		b.WriteByte(':')
		switch v := c.value.(type) {
		case string:
			b.WriteString(jsonString(v))
		case bool:
			b.WriteString(strconv.FormatBool(v))
		case int64:
			b.WriteString(strconv.FormatInt(v, 10))
		}
	}
	b.WriteByte('}')
	return b.String()
}

// headerSegment is base64url of {"alg":"HS256","typ":"JWT"}, as JSON.stringify writes it.
const headerSegment = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

func signClaims(claims []claim, secret string) string {
	body := b64url([]byte(encodeClaims(claims)))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(headerSegment + "." + body))
	return headerSegment + "." + body + "." + b64url(mac.Sum(nil))
}

// SignHS256 signs a payload given as ordered key/value pairs (string, bool or
// integer values) as a compact HS256 JWT keyed with the UTF-8 bytes of secret.
// It panics on an odd number of arguments or an unsupported value type, which
// are programming errors rather than runtime conditions.
func SignHS256(secret string, keyValues ...any) string {
	if len(keyValues)%2 != 0 {
		panic("reader.SignHS256: key/value pairs expected")
	}
	claims := make([]claim, 0, len(keyValues)/2)
	for i := 0; i < len(keyValues); i += 2 {
		k, ok := keyValues[i].(string)
		if !ok {
			panic("reader.SignHS256: keys must be strings")
		}
		switch v := keyValues[i+1].(type) {
		case string, bool, int64:
			claims = append(claims, claim{k, v})
		case int:
			claims = append(claims, claim{k, int64(v)})
		default:
			panic("reader.SignHS256: values must be string, bool or integer")
		}
	}
	return signClaims(claims, secret)
}

// newJTI is 16 random bytes, base64url: the same shape as the Node helper's jti.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return b64url(b[:]), nil
}
