# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Velar** (formerly PromptShield) is a local HTTP/HTTPS proxy with MITM support for AI traffic. It detects and masks PII/secrets in outbound requests to AI providers, then restores original values in responses. All processing is local — nothing is sent to external services.

## Commands

```bash
# Build both binaries (velar CLI + velard daemon)
make build

# Run all tests with race detector
make test

# Run a single package's tests
go test ./internal/sanitizer/... -run TestSanitize

# Run a single test
go test ./internal/sanitizer/... -run TestSanitize/email -v

# Test ONNX NER detector (requires Python venv with numpy + onnxruntime)
make test-ner

# Run the proxy directly (without daemonizing)
go run ./cmd/velar daemon

# Start as background daemon (requires make build first)
./bin/velar start
```

## Architecture

The project produces two binaries:

- **`cmd/velar`** — CLI that manages the daemon lifecycle (`start`, `stop`, `restart`, `status`, `logs`, `stats`, `ca`, `proxy`, `model`)
- **`cmd/velard`** — The actual daemon process spawned by `velar start`

### Request Flow

```
Client -> Proxy.handle() -> policy.Engine.Evaluate()
  -> if CONNECT + MITM domain: mitm.Handler.HandleMITM()
  -> if CONNECT + tunnel: handleTunnel()
  -> if HTTP: handleHTTP()
    -> Inspector.InspectRequest()  [sanitize outbound]
    -> upstream RoundTrip
    -> Inspector.InspectResponse() [restore inbound]
```

### Key Packages

| Package | Role |
|---|---|
| `internal/proxy` | Core HTTP proxy; routes to MITM or tunnel based on policy |
| `internal/proxy/mitm` | MITM handler: TLS intercept via per-host leaf certs signed by local CA; uses `singleConnListener` pattern |
| `internal/sanitizer` | `SanitizingInspector` implements the `Inspector` interface; JSON-aware masking with fallback to full-text |
| `internal/detect` | Detection backends: `RegexDetector` (fast), `ONNXNERDetector` (Python subprocess), `HybridDetector` (combines both) |
| `internal/policy` | Rule engine: evaluates `allow`/`block`/`mitm` decisions per host |
| `internal/session` | Per-request store mapping placeholders -> originals, keyed by session ID propagated via context |
| `internal/config` | YAML/JSON config loader with custom lite parser (no external YAML dep); env overrides `VELAR_PORT`, `VELAR_LOG_FILE` |
| `internal/audit` | JSONL audit logger for request/response entries |
| `internal/stats` | In-memory stats collector for `velar stats` command |
| `internal/classifier` | Host classifier (stub — used as hook for future classification) |
| `internal/notifier` | macOS `NSUserNotification` wrapper (no-op on other platforms) |
| `internal/systemproxy` | macOS `networksetup` wrapper to toggle system HTTP/HTTPS proxy |
| `internal/models` | ONNX model registry and downloader for `velar model` commands |

### Sanitization Pipeline

1. `SanitizingInspector.InspectRequest()` reads the JSON body (POST only, `application/json`, ≤256 KB).
2. Tries `HybridDetector` (regex + optional ONNX NER) via `sanitizeJSONFields()` targeting configured `sanitize_keys`.
3. Falls back to legacy `Sanitizer.Sanitize()` via `sanitizeJSONFieldsWithSanitizer()`.
4. Stores `{placeholder -> original}` mapping in `session.Store` under the request's session ID.
5. `InspectResponse()` looks up the session and restores placeholders in the response body.

### MITM TLS

- `mitm.CAStore` manages a local root CA at `~/.velar/ca/` (generated via `velar ca init`).
- Leaf certificates are generated on-demand and cached per hostname.
- The proxy responds `200 Connection Established` to CONNECT, then hijacks the conn and runs a single-connection `http.Server` on top of the TLS-wrapped socket.

### Config

Config file: `~/.velar/config.yaml` (falls back to `~/.promptshield/` for legacy users).

The config parser is a custom line-by-line YAML scanner (`parseYAMLLite`) — no third-party YAML library. JSON config is also supported.

### ONNX NER

The ONNX NER detector (`internal/detect/onnx_ner_detector.go`) shells out to a Python subprocess. It requires a Python virtualenv with `numpy` and `onnxruntime`, and a model downloaded via `velar model download`. It is **disabled by default** in config.

Build tags control the ONNX runtime backend:
- `onnx_ner_detector.go` / `onnx_ner_detector_test.go` — real backend (uses `github.com/yalue/onnxruntime_go`)
- `onnx_runtime_backend_stub.go` — stub used when onnxruntime_go is absent

### Module

Module name is `velar` (not the directory name). Import paths are `velar/internal/...`.
