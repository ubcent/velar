# Configuration

Velar loads configuration from:

```text
~/.velar/config.yaml
```

If the file does not exist, Velar starts with defaults and creates required local directories as needed.

## Full Example

```yaml
port: 8080
log_file: ~/.velar/audit.log

mitm:
  enabled: true
  domains:
    - api.openai.com
    - chat.openai.com
  log_request_response_bodies: true
  log_body_disabled_domains:
    - auth.openai.com
  log_body_enabled_domains:
    - api.openai.com

sanitizer:
  enabled: true
  types:
    - email
    - phone
    - api_key
  confidence_threshold: 0.8
  max_replacements: 100

notifications:
  enabled: true

rules:
  - id: allow-all
    action: allow

  - id: block-openai
    match:
      host_contains: openai.com
    action: block

  - id: mitm-openai
    match:
      host_contains: openai.com
    action: mitm
```

## Sections

### `port`

- TCP port for the local proxy listener.
- Default: `8080`.

### `log_file`

- Destination for JSONL audit logs.
- Supports `~/` home expansion.
- Default: `~/.velar/audit.log`.

### `mitm`

Controls TLS interception behavior.

- `enabled`: global switch for MITM behavior
- `domains`: allowlist of domains eligible for interception
- `log_request_response_bodies`: default behavior for request/response preview logging in audit
- `log_body_disabled_domains`: domains where body preview logging is always disabled
- `log_body_enabled_domains`: domains where body preview logging is always enabled (useful when the global switch is off)

If `enabled: false`, Velar stays in tunnel behavior for HTTPS.

### `sanitizer`

Controls content redaction during inspected traffic.

- `enabled`: turn sanitization on/off
- `types`: detector types to apply (for example: `email`, `phone`, `api_key`, `jwt`)
- `confidence_threshold`: optional detection threshold
- `max_replacements`: upper bound for redactions in one payload

### `notifications`

Controls macOS system notifications when sanitizer detections occur.

- `enabled`: turn notifications on/off
- default: `true`

### `rules`

Ordered policy rules evaluated top-to-bottom. Each rule includes:

- `id`: rule identifier
- `match`: host match definition (`host` or `host_contains`)
- `action`: `allow`, `block`, or `mitm`

A common baseline is a final catch-all allow rule.

## Rule Examples

### Block a domain

```yaml
rules:
  - id: block-openai
    match:
      host_contains: openai.com
    action: block
```

### Allow only specific hosts

```yaml
rules:
  - id: allow-anthropic
    match:
      host: api.anthropic.com
    action: allow

  - id: block-rest
    action: block
```

### Require MITM for selected domains

```yaml
mitm:
  enabled: true
  domains:
    - api.openai.com

rules:
  - id: mitm-openai
    match:
      host: api.openai.com
    action: mitm

  - id: allow-others
    action: allow
```

### Configure per-domain request/response preview logging

```yaml
mitm:
  enabled: true
  log_request_response_bodies: true
  log_body_disabled_domains:
    - auth.openai.com

  # You can also invert behavior: disable globally and enable only chosen domains
  # log_request_response_bodies: false
  # log_body_enabled_domains:
  #   - api.openai.com
```

`log_body_disabled_domains` has priority over `log_body_enabled_domains`. Domain patterns support exact hosts and wildcards like `*.anthropic.com`.

## Environment Variables

Velar supports the following environment overrides:

- `VELAR_PORT`
- `VELAR_LOG_FILE`
- `PYTHON_BIN` (path to the Python interpreter used for ONNX NER)

Legacy variables are still accepted for migration (`PROMPTSHIELD_PORT`, `PROMPTSHIELD_LOG_FILE`), but Velar prints a deprecation warning and prefers `VELAR_*` when both are set.
