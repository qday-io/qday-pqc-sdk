package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"

	"github.com/qday-io/qday-pqc-server/internal/signer"
)

const maxBodyBytes = 1 << 20

type Server struct {
	signer *signer.Signer
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

func New(s *signer.Signer) *Server {
	h := &Server{signer: s}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("GET /v1/info", h.handleInfo)
	mux.HandleFunc("POST /v1/sign", h.handleSign)
	mux.HandleFunc("POST /v1/verify", h.handleVerify)
	h.mux = withLogging(mux)
	return h
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
		PublicKeyB64:  encodeBase64(s.signer.PublicKey()),
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
		SignatureB64: encodeBase64(sig),
		PublicKeyB64: encodeBase64(s.signer.PublicKey()),
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
	signature, err := decodeBase64("signature_b64", req.SignatureB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	pubKey := s.signer.PublicKey()
	if strings.TrimSpace(req.PublicKeyB64) != "" {
		pubKey, err = decodeBase64("public_key_b64", req.PublicKeyB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}

	alg := s.signer.Algorithm()
	if strings.TrimSpace(req.Algorithm) != "" {
		alg = req.Algorithm
	}

	ok, err := signer.Verify(alg, msg, signature, pubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Valid: ok})
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
