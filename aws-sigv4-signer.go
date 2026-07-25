/*
The following code is a proof of concept:
Project Title: aws_sigv4_signer.go
Goal or Aim:
* As a Proof Of Concept to test interation of objects with a numeric value.
ToDo:
-

written by Caddyshack2175

*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"gopkg.in/yaml.v3"
)

const (
	requestTimeout            = 30 * time.Second
	maxCredentialResponseSize = 2 << 20
)

/*
	###
	# Main Function
	###
*/
/*	########################################################################################################	*/
func main() {
	method := flag.String("X", "GET", "HTTP method (GET, POST, PUT, PATCH, DELETE)")
	body := flag.String("b", "", "Request body (JSON string)")
	configFile := flag.String("c", "credentials.yaml", "Path to credentials YAML file")
	burpFile := flag.String("B", "credentials.burp", "Path to Burp credential request")
	region := flag.String("r", "", "AWS signing region (inferred from AWS URL when omitted)")
	service := flag.String("s", "", "AWS signing service (inferred from AWS URL when omitted)")
	outputFile := flag.String("o", "", "Replay -B, write resolved credentials to this YAML file, and exit (no request is sent; -r and -s are required)")
	headers := make(headerFlag)
	flag.Var(&headers, "H", "Custom header (can be used multiple times)")

	flag.Usage = func() {
		output := flag.CommandLine.Output()
		fmt.Fprintf(output, "Usage: sigv4 [options] <url>\n\n")
		fmt.Fprintln(output, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(output, "\nExamples:")
		fmt.Fprintln(output, "# GET request")
		fmt.Fprintln(output, "  sigv4 https://api.example.com/endpoint")
		fmt.Fprintln(output, "# POST request with body")
		fmt.Fprintln(output, `  sigv4 -X POST -b '{"key":"value"}' https://api.example.com/endpoint`)
		fmt.Fprintln(output, "# PUT request")
		fmt.Fprintln(output, `  sigv4 -X PUT -b '{"update":"data"}' https://api.example.com/resource/123`)
		fmt.Fprintln(output, "# DELETE request")
		fmt.Fprintln(output, "  sigv4 -X DELETE https://api.example.com/resource/123")
		fmt.Fprintln(output, "# Custom config file")
		fmt.Fprintln(output, "  sigv4 -c other-creds.yaml https://api.example.com/endpoint")
		fmt.Fprintln(output, "# POST with body and multiple headers")
		fmt.Fprintln(output, `  sigv4 -X POST -b '{"key":"value"}' -H 'X-Custom: value' https://api.example.com/endpoint`)
		fmt.Fprintln(output, "# All together")
		fmt.Fprintln(output, `  sigv4 -X POST -b '{"data":"test"}' -H 'X-Request-ID: 123' -c creds.yaml https://api.example.com/endpoint`)
		fmt.Fprintln(output, "# Generate a credentials.yaml for a role from a Burp request, no URL needed")
		fmt.Fprintln(output, "  sigv4 -B admin-role.burp -o admin-role.yaml -r eu-west-1 -s api")
	}

	flag.Parse()

	if *outputFile != "" {
		if err := generateCredentialsFile(*burpFile, *outputFile, *region, *service); err != nil {
			log.Fatal("Failed to generate credentials file: ", err)
		}
		return
	}

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	url := args[0]

	cfg, err := loadCredentials(*configFile, *burpFile, url, *region, *service)
	if err != nil {
		log.Fatal("Failed to load credentials: ", err)
	}
	
	//log.Printf("Using credentials from %s", source)

	// Convert body string to bytes
	var bodyBytes []byte
	if *body != "" {
		bodyBytes = []byte(*body)
	}

	if err := signAndSendRequest(*method, url, bodyBytes, headers, cfg); err != nil {
		log.Fatalf("Request failed: %v", err)
	}
}

/*	########################################################################################################	*/
/*
	###
	# Functions used inside the main loop
	###
*/

func (h headerFlag) String() string {
	return ""
}

func (h headerFlag) Set(value string) error {
	// Parse "Key: Value"
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid header format, expected 'Key: Value'")
	}
	h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	return nil
}

func loadConfig(filepath string) (*Config, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ---------------------------------------------------------------------------
// Credential loading: credentials.yaml or a replayed Burp request
// ---------------------------------------------------------------------------

type cognitoCredentialResponse struct {
	Credentials struct {
		AccessKeyID  string  `json:"AccessKeyId"`
		SecretKey    string  `json:"SecretKey"`
		SessionToken string  `json:"SessionToken"`
		Expiration   float64 `json:"Expiration"`
	} `json:"Credentials"`
}

func loadCredentials(configPath, burpPath, targetURL, regionOverride, serviceOverride string) (*Config, string, error) {
	cfg, err := loadConfig(configPath)
	if err == nil {
		if err := validateConfig(cfg); err != nil {
			return nil, "", fmt.Errorf("%s: %w", configPath, err)
		}
		return cfg, configPath, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("%s: %w", configPath, err)
	}

	cfg, err = fetchBurpCredentials(burpPath, &http.Client{Timeout: requestTimeout})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("neither %s nor %s exists", configPath, burpPath)
		}
		return nil, "", fmt.Errorf("%s: %w", burpPath, err)
	}

	inferredRegion, inferredService, err := inferSigningScope(targetURL)
	if err != nil && (regionOverride == "" || serviceOverride == "") {
		return nil, "", fmt.Errorf("%w; set both -r and -s for a custom endpoint", err)
	}
	cfg.Credentials.Region = firstNonEmpty(regionOverride, inferredRegion)
	cfg.Credentials.SigningService = firstNonEmpty(serviceOverride, inferredService)
	if err := validateConfig(cfg); err != nil {
		return nil, "", fmt.Errorf("%s: %w", burpPath, err)
	}
	return cfg, burpPath, nil
}

// generateCredentialsFile replays the Burp request at burpPath, resolves the
// temporary credentials from its response, and writes them out as a
// standard credentials.yaml-shaped file at outputPath. It does not contact
// any target URL, so region and service must be supplied explicitly rather
// than inferred. This is meant for pre-generating a credentials file per
// AWS role so it can be reused with -c until the temporary credentials
// expire, without re-running the Burp auth flow each time.
func generateCredentialsFile(burpPath, outputPath, region, service string) error {
	if region == "" || service == "" {
		return errors.New("generating a credentials file requires both -r and -s")
	}

	cfg, err := fetchBurpCredentials(burpPath, &http.Client{Timeout: requestTimeout})
	if err != nil {
		return fmt.Errorf("%s: %w", burpPath, err)
	}
	cfg.Credentials.Region = region
	cfg.Credentials.SigningService = service

	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("%s: %w", burpPath, err)
	}
	if err := saveConfig(outputPath, cfg); err != nil {
		return fmt.Errorf("%s: %w", outputPath, err)
	}
	log.Printf("Wrote credentials to %s", outputPath)
	return nil
}

func saveConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func fetchBurpCredentials(path string, client *http.Client) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	req, err := parseBurpRequest(raw)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credential request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCredentialResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read credential response: %w", err)
	}
	if len(body) > maxCredentialResponseSize {
		return nil, fmt.Errorf("credential response exceeds %d bytes", maxCredentialResponseSize)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("credential endpoint returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var result cognitoCredentialResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode credential response: %w", err)
	}
	cfg := &Config{}
	cfg.Credentials.AccessKey = result.Credentials.AccessKeyID
	cfg.Credentials.SecretKey = result.Credentials.SecretKey
	cfg.Credentials.SessionToken = result.Credentials.SessionToken
	return cfg, nil
}

func parseBurpRequest(raw []byte) (*http.Request, error) {
	normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	parts := bytes.SplitN(normalized, []byte("\n\n"), 2)
	if len(parts) != 2 {
		return nil, errors.New("Burp request has no header/body separator")
	}

	scanner := bufio.NewScanner(bytes.NewReader(parts[0]))
	if !scanner.Scan() {
		return nil, errors.New("Burp request is empty")
	}
	requestLine := strings.Fields(scanner.Text())
	if len(requestLine) != 3 {
		return nil, fmt.Errorf("invalid request line %q", scanner.Text())
	}

	headers := make(http.Header)
	var host string
	for scanner.Scan() {
		line := scanner.Text()
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header line %q", line)
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if strings.EqualFold(name, "Host") {
			host = value
			continue
		}
		if shouldCopyBurpHeader(name) {
			headers.Add(name, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Burp headers: %w", err)
	}
	if host == "" {
		return nil, errors.New("Burp request is missing Host header")
	}

	requestURL := requestLine[1]
	if parsed, err := url.Parse(requestURL); err != nil || !parsed.IsAbs() {
		requestURL = "https://" + host + requestURL
	}
	req, err := http.NewRequest(requestLine[0], requestURL, bytes.NewReader(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("create credential request: %w", err)
	}
	req.Header = headers
	req.Host = host
	return req, nil
}

func shouldCopyBurpHeader(name string) bool {
	switch strings.ToLower(name) {
	case "content-length", "accept-encoding", "connection", "proxy-connection", "te":
		return false
	default:
		return true
	}
}

func inferSigningScope(rawURL string) (string, string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return "", "", fmt.Errorf("cannot infer signing scope from URL %q", rawURL)
	}
	labels := strings.Split(parsed.Hostname(), ".")
	for i, label := range labels {
		if label == "execute-api" && i+1 < len(labels) {
			return labels[i+1], "execute-api", nil
		}
		if label == "appsync-api" && i+1 < len(labels) {
			return labels[i+1], "appsync", nil
		}
	}
	if len(labels) >= 4 && labels[len(labels)-2] == "amazonaws" {
		return labels[len(labels)-3], labels[len(labels)-4], nil
	}
	return "", "", fmt.Errorf("cannot infer AWS region and service from host %q", parsed.Hostname())
}

func validateConfig(cfg *Config) error {
	missing := make([]string, 0, 4)
	if cfg.Credentials.AccessKey == "" {
		missing = append(missing, "access key")
	}
	if cfg.Credentials.SecretKey == "" {
		missing = append(missing, "secret key")
	}
	if cfg.Credentials.Region == "" {
		missing = append(missing, "region")
	}
	if cfg.Credentials.SigningService == "" {
		missing = append(missing, "signing service")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// ---------------------------------------------------------------------------

func calculatePayloadHash(body []byte) string {
	if len(body) == 0 {
		return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}

func signAndSendRequest(method, url string, body []byte, headers headerFlag, cfg *Config) error {
	creds := aws.Credentials{
		AccessKeyID:     cfg.Credentials.AccessKey,
		SecretAccessKey: cfg.Credentials.SecretKey,
		SessionToken:    cfg.Credentials.SessionToken,
	}

	signer := v4.NewSigner(func(o *v4.SignerOptions) {
		o.LogSigning = true
	})

	// Create request with body
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return err
	}

	// Set default headers
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Calculate payload hash
	payloadHash := calculatePayloadHash(body)

	// Sign the request
	if err := signer.SignHTTP(
		context.Background(),
		creds,
		req,
		payloadHash,
		cfg.Credentials.SigningService,
		cfg.Credentials.Region,
		time.Now(),
	); err != nil {
		return err
	}

	// Make the request
	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Output response
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return err
	}

	return nil
}

/*	########################################################################################################	*/

// Config file data strcture
type Config struct {
	Credentials struct {
		AccessKey      string `yaml:"access_key"`
		SecretKey      string `yaml:"secret_key"`
		SessionToken   string `yaml:"session_token"`
		Region         string `yaml:"region"`
		SigningService string `yaml:"signing_service"`
	} `yaml:"credentials"`
}

// Custom flag type for headers
type headerFlag map[string]string
