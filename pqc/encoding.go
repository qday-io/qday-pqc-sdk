package pqc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// EncodeBase64 always emits RFC 4648 standard Base64 with padding.
// DecodeBase64 also accepts whitespace, missing padding, and the URL-safe alphabet.

var (
	// ErrMessageRequired is returned when neither message nor message_b64 is set.
	ErrMessageRequired = errors.New("message is required (UTF-8) or message_b64 (Base64)")
	// ErrMessageExclusive is returned when both message and message_b64 are set.
	ErrMessageExclusive = errors.New("provide either message (UTF-8) or message_b64 (Base64), not both")
	// ErrInvalidUTF8 is returned when message is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("message must be valid UTF-8")
)

// EncodeBase64 encodes data as RFC 4648 standard Base64 with padding.
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes an RFC 4648 Base64 string. field is included in error
// messages (for example "signature_b64").
func DecodeBase64(field, value string) ([]byte, error) {
	compact := compactBase64(value)
	if compact == "" {
		return nil, fmt.Errorf("%s is required (RFC 4648 Base64)", field)
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		out, err := enc.DecodeString(compact)
		if err == nil {
			if len(out) == 0 {
				return nil, fmt.Errorf("%s decoded to empty bytes", field)
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("invalid %s: expected RFC 4648 Base64", field)
}

func compactBase64(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// DecodeUTF8Message validates s as non-empty UTF-8.
func DecodeUTF8Message(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("message is required (UTF-8)")
	}
	if !utf8.ValidString(s) {
		return nil, ErrInvalidUTF8
	}
	return []byte(s), nil
}

// DecodeMessage accepts either UTF-8 text or Base64 raw bytes, not both.
func DecodeMessage(text, b64 string) ([]byte, error) {
	hasText := text != ""
	hasB64 := strings.TrimSpace(b64) != ""
	switch {
	case hasText && hasB64:
		return nil, ErrMessageExclusive
	case hasB64:
		return DecodeBase64("message_b64", b64)
	case hasText:
		return DecodeUTF8Message(text)
	default:
		return nil, ErrMessageRequired
	}
}
