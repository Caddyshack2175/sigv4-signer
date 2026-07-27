# AWS SigV4 Signer

**A command-line tool for re-signing HTTP requests with AWS Signature Version 4 — built to fuzz and replay against SigV4-protected endpoints during authorised security testing.**

> ⚠️ **For use only on systems you own or have written authorisation to test.** This tool exists to test the security of SigV4-protected APIs. Using it against systems you are not authorised to assess is illegal in most jurisdictions.

## The problem it solves

SigV4 request signing is often an effective barrier to security testing — not by design, but as a side effect. Because every request must carry a valid signature derived from AWS credentials, an intercepting proxy like Burp can't simply replay or fuzz captured traffic: the moment a request is modified, its signature no longer matches and the endpoint rejects it. Tamper with the payload, the signature breaks. That closes off the entire authenticated attack surface behind the signing layer — fuzzing, replay, and request manipulation all stop at the wall.

This tool reopens that surface for authorised testers. Given AWS credentials — including *temporary* credentials captured from an application's own signing handshake — it re-signs arbitrary requests so they pass validation. That means a tester can modify a request, sign it correctly, and send it through: fuzzing endpoint logic, replaying with altered parameters, and reaching the application behaviour that the signing layer would otherwise hide.

It is deliberately a proof of concept. It reads credentials directly rather than using the AWS SDK's credential provider chain, because the point is to work with credentials you've *captured during a test*, not credentials configured on your own machine.

## What it does

- `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and other HTTP methods
- JSON request bodies and repeated custom headers
- Long-lived AWS credentials, or temporary credentials with a session token
- Automatic temporary-credential retrieval by replaying a captured Burp request
- Configurable AWS region and signing service (inferred from standard AWS URLs, or set explicitly)
- A 30-second request timeout

> **Warning:** The credentials file contains secrets. Never commit a populated `credentials.yaml`. If credentials are exposed, revoke and replace them — removing the file from the latest commit does **not** remove them from Git history.

## Requirements

- Go 1.22 or later
- AWS credentials — configured, or capturable — with permission to call the target service

The module specifies the Go 1.23.10 toolchain, which Go may download automatically when a different compatible version is installed.

## Build

```bash
cd sigv4-signer
make build
```

The `sigv4` binary is created in the project directory. Run it there or move it onto your `PATH`.

## Credentials

### From a YAML file

```bash
cp credentials.example.yaml credentials.yaml
```

```yaml
credentials:
  access_key: "YOUR_ACCESS_KEY_ID"
  secret_key: "YOUR_SECRET_ACCESS_KEY"
  session_token: "YOUR_SESSION_TOKEN"   # required for temporary creds; leave "" for long-lived
  region: "eu-west-1"
  signing_service: "api"                # must match the target service, e.g. execute-api for API Gateway
```

Point at a file elsewhere with `-c`:

```bash
./sigv4 -c /secure/path/credentials.yaml https://example.api.eu-west-1.amazonaws.com/prod
```

### From a captured signing handshake (the interesting bit)

When an application signs its own requests, the temporary credentials it uses can often be captured from the signing handshake in Burp. If `credentials.yaml` is absent and `credentials.burp` is present, the tool replays the captured request, reads the temporary credentials from the JSON response, and holds them **in memory only — never written to disk**.

In Burp, **Copy to file** on the credential-issuing request, save it as `credentials.burp` in your working directory, then run the signer normally:

```bash
./sigv4 https://example.api.eu-west-1.amazonaws.com/prod/items
```

Credential source precedence:

1. YAML file from `-c` (default `credentials.yaml`)
2. Burp request from `-B` (default `credentials.burp`)

For custom domains, where region/service can't be inferred from the URL, set them explicitly:

```bash
./sigv4 -r eu-west-1 -s api https://api.example.com/items
```

> `credentials.burp` can contain live auth tokens — protect it like a password. It is gitignored by default.

### Pre-generating credentials for multiple roles

Replaying the Burp handshake on every call re-runs the whole auth flow each time. When testing multiple IAM roles, `-o` replays it once, writes the resolved temporary credentials to a `credentials.yaml`-shaped file, and exits without sending anything to a target:

```bash
./sigv4 -B admin-role.burp    -o admin-role.yaml    -r eu-west-1 -s api
./sigv4 -B readonly-role.burp -o readonly-role.yaml -r eu-west-1 -s api
```

Because no request is sent in this mode, `-r` and `-s` are required. Reuse each file while its temporary credentials remain valid; regenerate when they expire. `-o` output files contain live secrets — treat them like `credentials.yaml`.

## Usage

```
sigv4 [options] <url>

  -B string   Path to Burp credential request (default "credentials.burp")
  -H value    Custom header in "Key: Value" form; may be repeated
  -X string   HTTP method (default "GET")
  -b string   Request body (JSON string)
  -c string   Path to credentials YAML file (default "credentials.yaml")
  -o string   Replay -B, write resolved credentials to this file, and exit (-r and -s required)
  -r string   AWS signing region
  -s string   AWS signing service
```

The URL must include its scheme. Options must appear before the URL.

## Examples

```bash
# GET
./sigv4 https://example.api.eu-west-1.amazonaws.com/prod/items

# POST with a JSON body
./sigv4 -X POST -b '{"name":"example"}' \
  https://example.api.eu-west-1.amazonaws.com/prod/items

# Fuzzing an ID with custom headers, re-signed each time
./sigv4 -X PUT -b '{"enabled":true}' \
  -H 'X-Request-ID: 123' -H 'Accept: application/json' \
  https://example.api.eu-west-1.amazonaws.com/prod/items/42
```

## Request and response behaviour

- `Accept: application/json` added by default; `Content-Type: application/json` added when a body is supplied.
- A custom header with the same name replaces the default.
- The response body is written to standard output.
- Status codes and response headers are not currently printed.
- HTTP error statuses do not set a non-zero exit code by themselves; connection, signing, configuration, and response-reading errors do.

## Development

```bash
cd sigv4-signer
make test
```

The suite covers payload hashing, header parsing, YAML and Burp credential loading, signing-scope inference, SigV4 authorization headers, request bodies, custom headers, temporary-credential session tokens, response output, and common failure paths. HTTP tests use in-process test servers and never call AWS — the suite is fast, deterministic, and runnable without credentials.

```
make          # tidy deps, build, and test
make build    # build ./sigv4
make install  # install into $GOBIN or $GOPATH/bin
make clean    # remove the local build
```

## Project layout

```
sigv4-signer/
├── aws-sigv4-signer.go        # CLI, signing, and credential loading (YAML + Burp)
├── aws-sigv4-signer_test.go
├── credentials.example.yaml
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## License

MIT
