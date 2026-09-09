package server

import (
	"encoding/base64"
	"testing"
)

func TestEncodeDecodeBase64RoundTrip(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xff, 0x7e}
	encoded := encodeBase64(raw)
	got, err := decodeBase64("field", encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("got %x, want %x", got, raw)
	}
}

func TestDecodeBase64AcceptsWrappedAndURLSafe(t *testing.T) {
	raw := []byte("hello pqc payload")
	std := base64.StdEncoding.EncodeToString(raw)
	wrapped := std[:8] + "\n" + std[8:] + " \t"
	url := base64.URLEncoding.EncodeToString(raw)
	rawStd := base64.RawStdEncoding.EncodeToString(raw)

	for _, in := range []string{std, wrapped, url, rawStd} {
		got, err := decodeBase64("signature_b64", in)
		if err != nil {
			t.Fatalf("decode %q: %v", in, err)
		}
		if string(got) != string(raw) {
			t.Fatalf("decode %q: got %q", in, got)
		}
	}
}

func TestDecodeBase64RejectsInvalid(t *testing.T) {
	if _, err := decodeBase64("signature_b64", "%%%"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := decodeBase64("signature_b64", "   "); err == nil {
		t.Fatal("expected required error")
	}
}

func TestDecodeUTF8Message(t *testing.T) {
	got, err := decodeUTF8Message("hello pqc")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello pqc" {
		t.Fatalf("got %q", got)
	}
	if _, err := decodeUTF8Message(""); err == nil {
		t.Fatal("expected required error")
	}
	if _, err := decodeUTF8Message(string([]byte{0xff, 0xfe})); err == nil {
		t.Fatal("expected invalid UTF-8 error")
	}
}

func TestDecodeMessageExclusive(t *testing.T) {
	if _, err := decodeMessage("hi", encodeBase64([]byte("hi"))); err == nil {
		t.Fatal("expected exclusive error")
	}
	if _, err := decodeMessage("", ""); err == nil {
		t.Fatal("expected required error")
	}
	got, err := decodeMessage("", encodeBase64([]byte{0x00}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != 0x00 {
		t.Fatalf("got %x", got)
	}
}
