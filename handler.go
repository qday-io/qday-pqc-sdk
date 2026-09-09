package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

const maxBodyBytes = 1 << 20

type Server struct {
	signer *Signer
	mux    http.Handler
}

type errorBody struct {
	Error string `json:"error"`
}

type signRequest struct {
	Message    string `json:"message"`
	MessageB64 string `json:"message_b64"`
}

type signResponse struct {
	Algorithm    string `json:"algorithm"`
	SignatureB64 string `json:"signature_b64"`
	PublicKeyB64 string `json:"public_key_b64"`
}

type verifyRequest struct {
	Message      string `json:"message"`
	MessageB64   string `json:"message_b64"`
	SignatureB64 string `json:"signature_b64"`
	PublicKeyB64 string `json:"public_key_b64"`
	Algorithm    string `json:"algorithm"`
}

type verifyResponse struct {
	Valid bool `json:"valid"`
}

type infoResponse struct {
	LiboqsVersion string               `json:"liboqs_version"`
	Algorithm     string               `json:"algorithm"`
	PublicKeyB64  string               `json:"public_key_b64"`
	Details       oqs.SignatureDetails `json:"details"`
}

func NewServer(signer *Signer) *Server {
	s := &Server{signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/info", s.handleInfo)
	mux.HandleFunc("POST /v1/sign", s.handleSign)
	mux.HandleFunc("POST /v1/verify", s.handleVerify)
	s.mux = withLogging(mux)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, infoResponse{
		LiboqsVersion: oqs.LiboqsVersion(),
		Algorithm:     s.signer.Algorithm(),
		PublicKeyB64:  base64.StdEncoding.EncodeToString(s.signer.PublicKey()),
		Details:       s.signer.Details(),
	})
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	msg, err := decodeMessage(req.Message, req.MessageB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	sig, err := s.signer.Sign(msg)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, signResponse{
		Algorithm:    s.signer.Algorithm(),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
		PublicKeyB64: base64.StdEncoding.EncodeToString(s.signer.PublicKey()),
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	msg, err := decodeMessage(req.Message, req.MessageB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.SignatureB64) == "" {
		writeError(w, http.StatusBadRequest, errors.New("signature_b64 is required"))
		return
	}

	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid signature_b64"))
		return
	}

	pubKey := s.signer.PublicKey()
	if strings.TrimSpace(req.PublicKeyB64) != "" {
		pubKey, err = base64.StdEncoding.DecodeString(req.PublicKeyB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid public_key_b64"))
			return
		}
	}

	alg := s.signer.Algorithm()
	if strings.TrimSpace(req.Algorithm) != "" {
		alg = req.Algorithm
	}

	ok, err := Verify(alg, msg, signature, pubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Valid: ok})
}

func decodeMessage(text, b64 string) ([]byte, error) {
	hasText := text != ""
	hasB64 := strings.TrimSpace(b64) != ""
	switch {
	case hasText && hasB64:
		return nil, errors.New("provide either message or message_b64, not both")
	case hasB64:
		msg, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, errors.New("invalid message_b64")
		}
		if len(msg) == 0 {
			return nil, errors.New("message is required")
		}
		return msg, nil
	case hasText:
		return []byte(text), nil
	default:
		return nil, errors.New("message is required")
	}
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, errorBody{Error: err.Error()})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration", time.Since(start),
		)
	})
}
