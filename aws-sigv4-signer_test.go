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

func TestParseBurpRequest(t *testing.T) {
	raw := "POST / HTTP/2\r\nHost: cognito-identity.eu-west-1.amazonaws.com\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: 2\r\n\r\n{}"
	req, err := parseBurpRequest([]byte(raw))
	if err != nil {
		t.Fatalf("parseBurpRequest returned error: %v", err)
	}
	if req.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if req.URL.String() != "https://cognito-identity.eu-west-1.amazonaws.com/" {
		t.Errorf("URL = %q", req.URL.String())
	}
	if req.Header.Get("Content-Length") != "" {
		t.Error("captured Content-Length should be recalculated")
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "{}" {
		t.Errorf("body = %q, want {}", body)
	}
}

func TestFetchBurpCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "AWSCognitoIdentityService.GetCredentialsForIdentity" {
			t.Errorf("unexpected X-Amz-Target %q", r.Header.Get("X-Amz-Target"))
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = io.WriteString(w, `{"Credentials":{"AccessKeyId":"AKIDEXAMPLE","SecretKey":"secret","SessionToken":"token","Expiration":1784816088}}`)
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	raw := "POST " + server.URL + "/ HTTP/1.1\nHost: " + host + "\nX-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity\n\n{}"
	path := filepath.Join(t.TempDir(), "credentials.burp")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write Burp request: %v", err)
	}

	cfg, err := fetchBurpCredentials(path, server.Client())
	if err != nil {
		t.Fatalf("fetchBurpCredentials returned error: %v", err)
	}
	if cfg.Credentials.AccessKey != "AKIDEXAMPLE" ||
		cfg.Credentials.SecretKey != "secret" ||
		cfg.Credentials.SessionToken != "token" {
		t.Error("response credentials were not mapped correctly")
	}
}

func TestInferSigningScope(t *testing.T) {
	region, service, err := inferSigningScope("https://abc.execute-api.eu-west-2.amazonaws.com/prod")
	if err != nil {
		t.Fatalf("inferSigningScope returned error: %v", err)
	}
	if region != "eu-west-2" || service != "execute-api" {
		t.Errorf("scope = %s/%s, want eu-west-2/execute-api", region, service)
	}
}

func TestInferSigningScope_AppSync(t *testing.T) {
	region, service, err := inferSigningScope("https://xyz.appsync-api.us-east-1.amazonaws.com/graphql")
	if err != nil {
		t.Fatalf("inferSigningScope returned error: %v", err)
	}
	if region != "us-east-1" || service != "appsync" {
		t.Errorf("scope = %s/%s, want us-east-1/appsync", region, service)
	}
}

func TestInferSigningScope_GenericServiceRegionHost(t *testing.T) {
	region, service, err := inferSigningScope("https://sts.eu-west-2.amazonaws.com/")
	if err != nil {
		t.Fatalf("inferSigningScope returned error: %v", err)
	}
	if region != "eu-west-2" || service != "sts" {
		t.Errorf("scope = %s/%s, want eu-west-2/sts", region, service)
	}
}

func TestInferSigningScope_VirtualHostedS3Bucket(t *testing.T) {
	region, service, err := inferSigningScope("https://my-bucket.s3.eu-west-2.amazonaws.com/key")
	if err != nil {
		t.Fatalf("inferSigningScope returned error: %v", err)
	}
	if region != "eu-west-2" || service != "s3" {
		t.Errorf("scope = %s/%s, want eu-west-2/s3", region, service)
	}
}

func TestInferSigningScope_GlobalServiceWithoutRegionFails(t *testing.T) {
	_, _, err := inferSigningScope("https://iam.amazonaws.com/")
	if err == nil {
		t.Error("expected an error for a region-less global endpoint, got nil")
	}
}

func TestInferSigningScope_CustomDomainFails(t *testing.T) {
	_, _, err := inferSigningScope("https://api.example.com/items")
	if err == nil {
		t.Error("expected an error for a non-AWS host, got nil")
	}
}

func TestInferSigningScope_InvalidURL(t *testing.T) {
	_, _, err := inferSigningScope("://not-a-valid-url")
	if err == nil {
		t.Error("expected an error for an invalid URL, got nil")
	}
}

// ---------------------------------------------------------------------------
// parseBurpRequest edge cases
// ---------------------------------------------------------------------------

func TestParseBurpRequest_AbsoluteRequestLineURI(t *testing.T) {
	raw := "GET https://internal.example.com:8443/creds HTTP/1.1\nHost: proxy.local\n\n"
	req, err := parseBurpRequest([]byte(raw))
	if err != nil {
		t.Fatalf("parseBurpRequest returned error: %v", err)
	}
	if req.URL.String() != "https://internal.example.com:8443/creds" {
		t.Errorf("URL = %q, want the absolute URI from the request line", req.URL.String())
	}
}

func TestParseBurpRequest_PreservesAuthAndCookieHeaders(t *testing.T) {
	raw := "GET /creds HTTP/1.1\nHost: example.com\nAuthorization: Bearer abc123\nCookie: session=xyz\n\n"
	req, err := parseBurpRequest([]byte(raw))
	if err != nil {
		t.Fatalf("parseBurpRequest returned error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer abc123" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer abc123")
	}
	if got := req.Header.Get("Cookie"); got != "session=xyz" {
		t.Errorf("Cookie header = %q, want %q", got, "session=xyz")
	}
}

func TestParseBurpRequest_StripsHopByHopHeaders(t *testing.T) {
	raw := "GET /creds HTTP/1.1\nHost: example.com\nConnection: keep-alive\nProxy-Connection: keep-alive\nTE: trailers\nAccept-Encoding: gzip\n\n"
	req, err := parseBurpRequest([]byte(raw))
	if err != nil {
		t.Fatalf("parseBurpRequest returned error: %v", err)
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "TE", "Accept-Encoding"} {
		if got := req.Header.Get(name); got != "" {
			t.Errorf("%s header = %q, want it stripped", name, got)
		}
	}
}

func TestParseBurpRequest_RepeatedHeaderPreservesAllValues(t *testing.T) {
	raw := "GET /creds HTTP/1.1\nHost: example.com\nCookie: a=1\nCookie: b=2\n\n"
	req, err := parseBurpRequest([]byte(raw))
	if err != nil {
		t.Fatalf("parseBurpRequest returned error: %v", err)
	}
	got := req.Header.Values("Cookie")
	if len(got) != 2 || got[0] != "a=1" || got[1] != "b=2" {
		t.Errorf("Cookie values = %v, want [a=1 b=2]", got)
	}
}

func TestParseBurpRequest_MissingSeparator(t *testing.T) {
	raw := "GET /creds HTTP/1.1\nHost: example.com\n"
	if _, err := parseBurpRequest([]byte(raw)); err == nil {
		t.Error("expected an error when the header/body separator is missing, got nil")
	}
}

func TestParseBurpRequest_MissingHostHeader(t *testing.T) {
	raw := "GET /creds HTTP/1.1\nX-Foo: bar\n\n"
	if _, err := parseBurpRequest([]byte(raw)); err == nil {
		t.Error("expected an error when the Host header is missing, got nil")
	}
}

func TestParseBurpRequest_InvalidRequestLine(t *testing.T) {
	raw := "GET\nHost: example.com\n\n"
	if _, err := parseBurpRequest([]byte(raw)); err == nil {
		t.Error("expected an error for a malformed request line, got nil")
	}
}

func TestParseBurpRequest_InvalidHeaderLine(t *testing.T) {
	raw := "GET /creds HTTP/1.1\nHost: example.com\nNotAHeader\n\n"
	if _, err := parseBurpRequest([]byte(raw)); err == nil {
		t.Error("expected an error for a header line with no colon, got nil")
	}
}

// ---------------------------------------------------------------------------
// fetchBurpCredentials edge cases
// ---------------------------------------------------------------------------

func TestFetchBurpCredentials_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.burp")
	_, err := fetchBurpCredentials(path, http.DefaultClient)
	if !os.IsNotExist(err) {
		t.Errorf("expected a not-exist error, got %v", err)
	}
}

func TestFetchBurpCredentials_NonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "access denied")
	}))
	defer server.Close()

	path := writeBurpRequest(t, server.URL)
	_, err := fetchBurpCredentials(path, server.Client())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("expected an error mentioning the 403 status, got %v", err)
	}
}

func TestFetchBurpCredentials_ResponseTooLarge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, maxCredentialResponseSize+1))
	}))
	defer server.Close()

	path := writeBurpRequest(t, server.URL)
	_, err := fetchBurpCredentials(path, server.Client())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected an error about exceeding the size limit, got %v", err)
	}
}

func TestFetchBurpCredentials_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "not json")
	}))
	defer server.Close()

	path := writeBurpRequest(t, server.URL)
	_, err := fetchBurpCredentials(path, server.Client())
	if err == nil {
		t.Error("expected an error for a malformed JSON response, got nil")
	}
}

func TestFetchBurpCredentials_STSShapedResponseLeavesSecretKeyEmpty(t *testing.T) {
	// STS responses use "SecretAccessKey" rather than Cognito's "SecretKey";
	// this documents that mismatch rather than silently signing with a
	// missing secret (loadCredentials.validateConfig catches it downstream).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"Credentials":{"AccessKeyId":"AKIDEXAMPLE","SecretAccessKey":"secret","SessionToken":"token"}}`)
	}))
	defer server.Close()

	path := writeBurpRequest(t, server.URL)
	cfg, err := fetchBurpCredentials(path, server.Client())
	if err != nil {
		t.Fatalf("fetchBurpCredentials returned error: %v", err)
	}
	if cfg.Credentials.SecretKey != "" {
		t.Errorf("SecretKey = %q, want empty for an STS-shaped response", cfg.Credentials.SecretKey)
	}
}

// writeBurpRequest writes a minimal valid Burp request file targeting the
// given httptest server URL and returns its path.
func writeBurpRequest(t *testing.T, serverURL string) string {
	t.Helper()
	host := strings.TrimPrefix(serverURL, "http://")
	raw := "POST " + serverURL + "/ HTTP/1.1\nHost: " + host + "\n\n{}"
	path := filepath.Join(t.TempDir(), "credentials.burp")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write Burp request: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// validateConfig / firstNonEmpty
// ---------------------------------------------------------------------------

func TestValidateConfig_MissingFields(t *testing.T) {
	cfg := &Config{}
	cfg.Credentials.AccessKey = "AKIDEXAMPLE"
	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("expected an error for incomplete credentials, got nil")
	}
	for _, field := range []string{"secret key", "region", "signing service"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error %q does not mention missing %q", err.Error(), field)
		}
	}
}

func TestValidateConfig_AllPresent(t *testing.T) {
	if err := validateConfig(testConfig()); err != nil {
		t.Errorf("unexpected error for a complete config: %v", err)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "c"); got != "c" {
		t.Errorf("firstNonEmpty = %q, want %q", got, "c")
	}
	if got := firstNonEmpty("a", "b"); got != "a" {
		t.Errorf("firstNonEmpty = %q, want %q", got, "a")
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("firstNonEmpty = %q, want empty string", got)
	}
}

// ---------------------------------------------------------------------------
// loadCredentials (YAML + Burp fallback integration)
// ---------------------------------------------------------------------------

func TestLoadCredentials_UsesYAMLWhenPresent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "credentials.yaml")
	content := `credentials:
  access_key: "AKIDEXAMPLE"
  secret_key: "secretkey"
  region: "eu-west-2"
  signing_service: "execute-api"
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	burpPath := filepath.Join(dir, "credentials.burp") // deliberately absent

	cfg, source, err := loadCredentials(configPath, burpPath, "https://example.com", "", "")
	if err != nil {
		t.Fatalf("loadCredentials returned error: %v", err)
	}
	if source != configPath {
		t.Errorf("source = %q, want %q", source, configPath)
	}
	if cfg.Credentials.AccessKey != "AKIDEXAMPLE" {
		t.Errorf("AccessKey = %q, want %q", cfg.Credentials.AccessKey, "AKIDEXAMPLE")
	}
}

func TestLoadCredentials_MalformedYAMLDoesNotFallBackToBurp(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(configPath, []byte("credentials: [not a map"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	burpPath := filepath.Join(dir, "credentials.burp") // absent; would produce a
	// different ("neither ... exists") error if loadCredentials fell through to it

	_, _, err := loadCredentials(configPath, burpPath, "https://example.com", "", "")
	if err == nil {
		t.Fatal("expected an error for malformed YAML, got nil")
	}
	if strings.Contains(err.Error(), "neither") {
		t.Errorf("error %q suggests it fell back to the Burp path instead of failing on the malformed YAML", err.Error())
	}
}

func TestLoadCredentials_FallsBackToBurpWhenYAMLMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"Credentials":{"AccessKeyId":"AKIDEXAMPLE","SecretKey":"secret","SessionToken":"token"}}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "credentials.yaml") // absent
	burpPath := writeBurpRequest(t, server.URL)

	cfg, source, err := loadCredentials(configPath, burpPath, "https://abc.execute-api.eu-west-2.amazonaws.com/prod", "", "")
	if err != nil {
		t.Fatalf("loadCredentials returned error: %v", err)
	}
	if source != burpPath {
		t.Errorf("source = %q, want %q", source, burpPath)
	}
	if cfg.Credentials.Region != "eu-west-2" || cfg.Credentials.SigningService != "execute-api" {
		t.Errorf("scope = %s/%s, want eu-west-2/execute-api", cfg.Credentials.Region, cfg.Credentials.SigningService)
	}
}

func TestLoadCredentials_NeitherSourceExists(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "credentials.yaml")
	burpPath := filepath.Join(dir, "credentials.burp")

	_, _, err := loadCredentials(configPath, burpPath, "https://example.com", "", "")
	if err == nil || !strings.Contains(err.Error(), "neither") {
		t.Errorf("expected an error mentioning both missing paths, got %v", err)
	}
}

func TestLoadCredentials_BurpCredentialsMissingSecretKeyFailsValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// STS-shaped response: "SecretAccessKey" instead of Cognito's "SecretKey".
		_, _ = io.WriteString(w, `{"Credentials":{"AccessKeyId":"AKIDEXAMPLE","SecretAccessKey":"secret","SessionToken":"token"}}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "credentials.yaml") // absent
	burpPath := writeBurpRequest(t, server.URL)

	_, _, err := loadCredentials(configPath, burpPath, "https://abc.execute-api.eu-west-2.amazonaws.com/prod", "", "")
	if err == nil || !strings.Contains(err.Error(), "secret key") {
		t.Errorf("expected an error mentioning the missing secret key, got %v", err)
	}
}

func TestLoadCredentials_CustomDomainRequiresBothOverrides(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"Credentials":{"AccessKeyId":"AKIDEXAMPLE","SecretKey":"secret","SessionToken":"token"}}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "credentials.yaml") // absent
	burpPath := writeBurpRequest(t, server.URL)

	_, _, err := loadCredentials(configPath, burpPath, "https://api.example.com/items", "eu-west-2", "")
	if err == nil || !strings.Contains(err.Error(), "-r and -s") {
		t.Errorf("expected an error requiring both -r and -s, got %v", err)
	}
}

func TestLoadCredentials_CustomDomainWithBothOverridesSucceeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"Credentials":{"AccessKeyId":"AKIDEXAMPLE","SecretKey":"secret","SessionToken":"token"}}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "credentials.yaml") // absent
	burpPath := writeBurpRequest(t, server.URL)

	cfg, _, err := loadCredentials(configPath, burpPath, "https://api.example.com/items", "eu-west-2", "custom-service")
	if err != nil {
		t.Fatalf("loadCredentials returned error: %v", err)
	}
	if cfg.Credentials.Region != "eu-west-2" || cfg.Credentials.SigningService != "custom-service" {
		t.Errorf("scope = %s/%s, want eu-west-2/custom-service", cfg.Credentials.Region, cfg.Credentials.SigningService)
	}
}

func TestLoadCredentials_OverrideTakesPrecedenceOverInferred(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"Credentials":{"AccessKeyId":"AKIDEXAMPLE","SecretKey":"secret","SessionToken":"token"}}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "credentials.yaml") // absent
	burpPath := writeBurpRequest(t, server.URL)

	// Region is inferable from the URL; only the service is overridden.
	cfg, _, err := loadCredentials(configPath, burpPath, "https://abc.execute-api.eu-west-2.amazonaws.com/prod", "", "custom-service")
	if err != nil {
		t.Fatalf("loadCredentials returned error: %v", err)
	}
	if cfg.Credentials.Region != "eu-west-2" {
		t.Errorf("Region = %q, want inferred %q", cfg.Credentials.Region, "eu-west-2")
	}
	if cfg.Credentials.SigningService != "custom-service" {
		t.Errorf("SigningService = %q, want override %q", cfg.Credentials.SigningService, "custom-service")
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
