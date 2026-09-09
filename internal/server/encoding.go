package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// JSON field encodings:
//   message          UTF-8 text
//   message_b64      RFC 4648 Base64 (standard alphabet)
//   signature_b64    RFC 4648 Base64 (standard alphabet)
//   public_key_b64   RFC 4648 Base64 (standard alphabet)
//
// Responses always emit standard Base64 with padding.
// Requests also accept whitespace, missing padding, and the URL-safe alphabet.

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decodeBase64(field, value string) ([]byte, error) {
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

func decodeUTF8Message(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("message is required (UTF-8)")
	}
	if !utf8.ValidString(s) {
		return nil, errors.New("message must be valid UTF-8")
	}
	return []byte(s), nil
}

func decodeMessage(text, b64 string) ([]byte, error) {
	hasText := text != ""
	hasB64 := strings.TrimSpace(b64) != ""
	switch {
	case hasText && hasB64:
		return nil, errors.New("provide either message (UTF-8) or message_b64 (Base64), not both")
	case hasB64:
		return decodeBase64("message_b64", b64)
	case hasText:
		return decodeUTF8Message(text)
	default:
		return nil, errors.New("message is required (UTF-8) or message_b64 (Base64)")
	}
}
