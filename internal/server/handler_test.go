package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qday-io/qday-pqc-server/internal/signer"
)

func TestAPISignVerify(t *testing.T) {
	testAPISignVerify(t, "ML-DSA-65")
}

func TestAPISignVerifyFalcon512(t *testing.T) {
	testAPISignVerify(t, "Falcon-512")
}

func testAPISignVerify(t *testing.T, alg string) {
	t.Helper()
	s, err := signer.Generate(alg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(s))
	t.Cleanup(ts.Close)

	res, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", res.StatusCode)
	}

	signBody, _ := json.Marshal(signRequest{Message: "hello pqc"})
	res, err = http.Post(ts.URL+"/v1/sign", "application/json", bytes.NewReader(signBody))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign status %d", res.StatusCode)
	}

	var signed signResponse
	if err := json.NewDecoder(res.Body).Decode(&signed); err != nil {
		t.Fatal(err)
	}
	if signed.SignatureB64 == "" || signed.PublicKeyB64 == "" {
		t.Fatalf("empty sign response: %+v", signed)
	}
	if signed.Algorithm != alg {
		t.Fatalf("algorithm = %q, want %q", signed.Algorithm, alg)
	}

	verifyBody, _ := json.Marshal(verifyRequest{
		Message:      "hello pqc",
		SignatureB64: signed.SignatureB64,
		PublicKeyB64: signed.PublicKeyB64,
	})
	res, err = http.Post(ts.URL+"/v1/verify", "application/json", bytes.NewReader(verifyBody))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var verified verifyResponse
	if err := json.NewDecoder(res.Body).Decode(&verified); err != nil {
		t.Fatal(err)
	}
	if !verified.Valid {
		t.Fatal("expected valid signature")
	}

	tampered, _ := json.Marshal(verifyRequest{
		Message:      "hello pqd",
		SignatureB64: signed.SignatureB64,
		PublicKeyB64: signed.PublicKeyB64,
	})
	res, err = http.Post(ts.URL+"/v1/verify", "application/json", bytes.NewReader(tampered))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&verified); err != nil {
		t.Fatal(err)
	}
	if verified.Valid {
		t.Fatal("expected invalid signature for tampered message")
	}
}

func TestAPISignBinaryMessage(t *testing.T) {
	s, err := signer.Generate("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(s))
	t.Cleanup(srv.Close)

	raw := []byte{0x00, 0x01, 0xff}
	body, _ := json.Marshal(signRequest{MessageB64: base64.StdEncoding.EncodeToString(raw)})
	res, err := http.Post(srv.URL+"/v1/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("sign status %d", res.StatusCode)
	}
}

func TestAPISignRequiresMessage(t *testing.T) {
	s, err := signer.Generate("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(s))
	t.Cleanup(srv.Close)

	res, err := http.Post(srv.URL+"/v1/sign", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

func TestAPIVerifyAcceptsURLSafeAndWrappedBase64(t *testing.T) {
	s, err := signer.Generate("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(s))
	t.Cleanup(srv.Close)

	signBody, _ := json.Marshal(signRequest{Message: "hello pqc"})
	res, err := http.Post(srv.URL+"/v1/sign", "application/json", bytes.NewReader(signBody))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var signed signResponse
	if err := json.NewDecoder(res.Body).Decode(&signed); err != nil {
		t.Fatal(err)
	}

	pubRaw, err := base64.StdEncoding.DecodeString(signed.PublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}

	wrappedSig := signed.SignatureB64[:8] + "\n" + signed.SignatureB64[8:]
	urlPub := base64.URLEncoding.EncodeToString(pubRaw)

	body, _ := json.Marshal(verifyRequest{
		Message:      "hello pqc",
		SignatureB64: wrappedSig,
		PublicKeyB64: urlPub,
	})
	res, err = http.Post(srv.URL+"/v1/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var verified verifyResponse
	if err := json.NewDecoder(res.Body).Decode(&verified); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || !verified.Valid {
		t.Fatalf("status=%d valid=%v", res.StatusCode, verified.Valid)
	}
}

func TestAPIRejectsInvalidBase64(t *testing.T) {
	s, err := signer.Generate("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(s))
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(verifyRequest{
		Message:      "hello pqc",
		SignatureB64: "not-valid-base64!!!",
	})
	res, err := http.Post(srv.URL+"/v1/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}
