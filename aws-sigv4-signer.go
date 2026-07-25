/*
The following code is a proof of concept:
Project Title: aws_sigv4_signer.go
Goal or Aim:
* As a Proof Of Concept to test interation of objects with a numeric value.
ToDo:
-

*/

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"gopkg.in/yaml.v3"
)

const (
	requestTimeout = 30 * time.Second
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
	}

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	url := args[0]

	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

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
