# AWS SigV4 Signer

A small, curl-like command-line tool for sending HTTP requests signed with
[AWS Signature Version 4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html).
It is useful for calling IAM-protected endpoints such as Amazon API Gateway
without writing a client application.

The tool supports:

- `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, and other HTTP methods
- JSON request bodies
- Repeated custom headers
- Long-lived AWS credentials or temporary credentials with a session token
- Configurable AWS region and signing service
- A 30-second request timeout

> [!WARNING]
> The credentials file contains secrets. Never commit a populated
> `credentials.yaml` file. If credentials have already been exposed, deactivate
> or revoke them and create replacements. Removing the file from the latest
> commit does not remove credentials from Git history.

## Requirements

- Go 1.22 or later
- AWS credentials with permission to call the target service

The module currently specifies the Go 1.23.10 toolchain, which Go may download
automatically when a different compatible Go version is installed.

## Build

```sh
cd sigv4-signer
make build
```

The resulting `sigv4` binary is created in the `sigv4-signer` directory. You can
run it there or move it to a directory on your `PATH`.

## Configure credentials

Copy the safe example file, then populate the local copy:

```sh
cp credentials.example.yaml credentials.yaml
```

The configuration has this structure:

```yaml
credentials:
  access_key: "YOUR_ACCESS_KEY_ID"
  secret_key: "YOUR_SECRET_ACCESS_KEY"
  session_token: "YOUR_SESSION_TOKEN"
  region: "eu-west-1"
  signing_service: "api"
```

`session_token` is required for temporary credentials and can be left empty for
long-lived credentials:

```yaml
  session_token: ""
```

The signing service must match the AWS service receiving the request. For
example, use `execute-api` for API Gateway.

To keep credentials elsewhere, pass their path with `-c`:

```sh
./sigv4 -c /secure/path/credentials.yaml https://example.execute-api.eu-west-2.amazonaws.com/prod
```

## Usage

```text
sigv4 [options] <url>

Options:
  -X string
        HTTP method (GET, POST, PUT, PATCH, DELETE) (default "GET")
  -b string
        Request body (JSON string)
  -c string
        Path to credentials YAML file (default "credentials.yaml")
  -H value
        Custom header in "Key: Value" form; may be repeated
```

The URL must include its scheme, such as `https://`. Options must appear before
the URL.

## Examples

Send a GET request:

```sh
./sigv4 https://example.execute-api.eu-west-2.amazonaws.com/prod/items
```

Send a POST request with a JSON body:

```sh
./sigv4 -X POST \
  -b '{"name":"example"}' \
  https://example.execute-api.eu-west-2.amazonaws.com/prod/items
```

Add one or more headers:

```sh
./sigv4 -X PUT \
  -b '{"enabled":true}' \
  -H 'X-Request-ID: 123' \
  -H 'Accept: application/json' \
  https://example.execute-api.eu-west-2.amazonaws.com/prod/items/42
```

Send a DELETE request with a different credentials file:

```sh
./sigv4 -X DELETE \
  -c /secure/path/api-credentials.yaml \
  https://example.execute-api.eu-west-2.amazonaws.com/prod/items/42
```

## Request and response behavior

- `Accept: application/json` is added by default.
- `Content-Type: application/json` is added when a non-empty body is supplied.
- A custom header with the same name replaces its default value.
- The response body is written directly to standard output.
- Response status codes and response headers are not currently printed.
- HTTP error statuses do not cause a non-zero exit code by themselves. Connection,
  signing, configuration, and response-reading errors do.

## Development

```sh
cd sigv4-signer
make test
```

The automated suite covers payload hashing, header parsing, configuration
loading, SigV4 authorization headers, request bodies, custom headers, temporary
credential session tokens, response output, and common failure paths. The HTTP
tests use a local in-process test server and do not call AWS.

Additional targets:

```sh
make          # Download/tidy dependencies, build, and test
make build    # Build ./sigv4
make install  # Install sigv4 into $GOBIN or $GOPATH/bin
make clean    # Remove the local build
```

## Project layout

```text
sigv4-signer/
├── aws-sigv4-signer_v3.go  # CLI and signing implementation
├── aws-sigv4-signer_v3_test.go
├── credentials.example.yaml
├── go.mod                  # Go module definition
├── go.sum                  # Dependency checksums
├── Makefile
└── README.md
```

This project is a proof of concept. In particular, it reads credentials directly
from YAML rather than using the standard AWS SDK credential provider chain.
