package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// calculatePayloadHash
// ---------------------------------------------------------------------------

func TestCalculatePayloadHash_EmptyBody(t *testing.T) {
	got := calculatePayloadHash(nil)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("empty body hash = %q, want %q", got, want)
	}

	// The hardcoded constant must actually match sha256("").
	sum := sha256.Sum256([]byte{})
	if got != hex.EncodeToString(sum[:]) {
		t.Errorf("empty body hash %q does not match sha256(\"\") = %q", got, hex.EncodeToString(sum[:]))
	}
}

func TestCalculatePayloadHash_NonEmptyBody(t *testing.T) {
	body := []byte(`{"key":"value"}`)
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])

	got := calculatePayloadHash(body)
	if got != want {
		t.Errorf("calculatePayloadHash(%q) = %q, want %q", body, got, want)
	}
}

// ---------------------------------------------------------------------------
// headerFlag
// ---------------------------------------------------------------------------

func TestHeaderFlagSet_Valid(t *testing.T) {
	h := make(headerFlag)
	if err := h.Set("X-Request-ID: 123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := h["X-Request-ID"]; got != "123" {
		t.Errorf("h[%q] = %q, want %q", "X-Request-ID", got, "123")
	}
}

func TestHeaderFlagSet_TrimsSpace(t *testing.T) {
	h := make(headerFlag)
	if err := h.Set("  X-Custom  :   spaced value  "); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := h["X-Custom"]; got != "spaced value" {
		t.Errorf("h[%q] = %q, want %q", "X-Custom", got, "spaced value")
	}
}

func TestHeaderFlagSet_ValueContainingColon(t *testing.T) {
	h := make(headerFlag)
	if err := h.Set("Authorization: Bearer abc:def"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := h["Authorization"]; got != "Bearer abc:def" {
		t.Errorf("h[%q] = %q, want %q", "Authorization", got, "Bearer abc:def")
	}
}

func TestHeaderFlagSet_InvalidFormat(t *testing.T) {
	h := make(headerFlag)
	if err := h.Set("NoColonHere"); err == nil {
		t.Error("expected an error for a header with no colon, got nil")
	}
}

func TestHeaderFlagString(t *testing.T) {
	h := make(headerFlag)
	if h.String() != "" {
		t.Errorf("String() = %q, want empty string", h.String())
	}
}

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

func TestLoadConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.yaml")
	content := `credentials:
  access_key: "AKIDEXAMPLE"
  secret_key: "secretkey"
  session_token: "sessiontoken"
  region: "eu-west-2"
  signing_service: "execute-api"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Credentials.AccessKey != "AKIDEXAMPLE" {
		t.Errorf("AccessKey = %q, want %q", cfg.Credentials.AccessKey, "AKIDEXAMPLE")
	}
	if cfg.Credentials.SecretKey != "secretkey" {
		t.Errorf("SecretKey = %q, want %q", cfg.Credentials.SecretKey, "secretkey")
	}
	if cfg.Credentials.SessionToken != "sessiontoken" {
		t.Errorf("SessionToken = %q, want %q", cfg.Credentials.SessionToken, "sessiontoken")
	}
	if cfg.Credentials.Region != "eu-west-2" {
		t.Errorf("Region = %q, want %q", cfg.Credentials.Region, "eu-west-2")
	}
	if cfg.Credentials.SigningService != "execute-api" {
		t.Errorf("SigningService = %q, want %q", cfg.Credentials.SigningService, "execute-api")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	_, err := loadConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Error("expected an error for a missing config file, got nil")
	}
}

func TestLoadConfig_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("credentials: [this is not a map"), 0o600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	_, err := loadConfig(path)
	if err == nil {
		t.Error("expected an error for malformed YAML, got nil")
	}
}

// ---------------------------------------------------------------------------
// signAndSendRequest
// ---------------------------------------------------------------------------

var authHeaderPattern = regexp.MustCompile(
	`^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/\d{8}/eu-west-2/execute-api/aws4_request, SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$`,
)

func testConfig() *Config {
	cfg := &Config{}
	cfg.Credentials.AccessKey = "AKIDEXAMPLE"
	cfg.Credentials.SecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	cfg.Credentials.SessionToken = ""
	cfg.Credentials.Region = "eu-west-2"
	cfg.Credentials.SigningService = "execute-api"
	return cfg
}

// captureStdout redirects os.Stdout for the duration of fn and returns
// whatever was written to it.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	original := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = original }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read captured stdout: %v", err)
	}
	return string(out)
}

func TestSignAndSendRequest_GETSignsAndSendsRequest(t *testing.T) {
	var gotAuth, gotAccept, gotAmzDate string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotAmzDate = r.Header.Get("X-Amz-Date")

		if r.Method != http.MethodGet {
			t.Errorf("server received method %q, want %q", r.Method, http.MethodGet)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("response body"))
	}))
	defer server.Close()

	out := captureStdout(t, func() {
		if err := signAndSendRequest(http.MethodGet, server.URL, nil, make(headerFlag), testConfig()); err != nil {
			t.Fatalf("signAndSendRequest returned error: %v", err)
		}
	})

	if out != "response body" {
		t.Errorf("stdout = %q, want %q", out, "response body")
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept header = %q, want %q", gotAccept, "application/json")
	}
	if gotAmzDate == "" {
		t.Error("X-Amz-Date header was not set on the outgoing request")
	}
	if !authHeaderPattern.MatchString(gotAuth) {
		t.Errorf("Authorization header %q does not match expected SigV4 format", gotAuth)
	}
}

func TestSignAndSendRequest_POSTBodyIsSignedAndForwarded(t *testing.T) {
	body := []byte(`{"key":"value"}`)
	wantHash := calculatePayloadHash(body)

	var gotBody []byte
	var gotContentType, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("server failed to read request body: %v", err)
		}
		gotContentType = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	captureStdout(t, func() {
		if err := signAndSendRequest(http.MethodPost, server.URL, body, make(headerFlag), testConfig()); err != nil {
			t.Fatalf("signAndSendRequest returned error: %v", err)
		}
	})

	if string(gotBody) != string(body) {
		t.Errorf("server received body %q, want %q", gotBody, body)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type header = %q, want %q", gotContentType, "application/json")
	}
	// The payload hash is part of the canonical request, so a correctly
	// signed request implies the signer used the right hash. We can at
	// least confirm the hash we independently computed for this body
	// matches what the signer would have used for an identical payload.
	if wantHash != calculatePayloadHash(gotBody) {
		t.Errorf("payload hash mismatch: forwarded body does not hash to %q", wantHash)
	}
	if !strings.Contains(gotAuth, "SignedHeaders=") {
		t.Errorf("Authorization header %q missing SignedHeaders", gotAuth)
	}
}

func TestSignAndSendRequest_CustomHeaderOverridesDefault(t *testing.T) {
	var gotAccept, gotCustom string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotCustom = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	headers := make(headerFlag)
	headers["Accept"] = "text/plain"
	headers["X-Custom"] = "custom-value"

	captureStdout(t, func() {
		if err := signAndSendRequest(http.MethodGet, server.URL, nil, headers, testConfig()); err != nil {
			t.Fatalf("signAndSendRequest returned error: %v", err)
		}
	})

	if gotAccept != "text/plain" {
		t.Errorf("Accept header = %q, want custom value %q", gotAccept, "text/plain")
	}
	if gotCustom != "custom-value" {
		t.Errorf("X-Custom header = %q, want %q", gotCustom, "custom-value")
	}
}

func TestSignAndSendRequest_SessionTokenIsSentWhenPresent(t *testing.T) {
	cfg := testConfig()
	cfg.Credentials.SessionToken = "AQoDYXdzEPT..."

	var gotToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Amz-Security-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	captureStdout(t, func() {
		if err := signAndSendRequest(http.MethodGet, server.URL, nil, make(headerFlag), cfg); err != nil {
			t.Fatalf("signAndSendRequest returned error: %v", err)
		}
	})

	if gotToken != cfg.Credentials.SessionToken {
		t.Errorf("X-Amz-Security-Token = %q, want %q", gotToken, cfg.Credentials.SessionToken)
	}
}

func TestSignAndSendRequest_InvalidURL(t *testing.T) {
	err := signAndSendRequest(http.MethodGet, "://not-a-valid-url", nil, make(headerFlag), testConfig())
	if err == nil {
		t.Error("expected an error for an invalid URL, got nil")
	}
}

func TestSignAndSendRequest_UnreachableServer(t *testing.T) {
	// Port 0 on localhost will not be listening; the request should fail
	// at the HTTP client stage after signing succeeds.
	err := signAndSendRequest(http.MethodGet, "http://127.0.0.1:0", nil, make(headerFlag), testConfig())
	if err == nil {
		t.Error("expected an error for an unreachable server, got nil")
	}
}
