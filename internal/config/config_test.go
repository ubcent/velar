package config

import (
	"strings"
	"testing"
)

func TestParseYAMLLiteSanitizerConfig(t *testing.T) {
	cfg := Default()
	err := parseYAMLLite(strings.NewReader(`sanitizer:
  enabled: true
  types:
    - email
    - api_key
  confidence_threshold: 0.7
  max_replacements: 5
`), &cfg)
	if err != nil {
		t.Fatalf("parseYAMLLite() error = %v", err)
	}
	if !cfg.Sanitizer.Enabled || len(cfg.Sanitizer.Types) != 2 || cfg.Sanitizer.Types[1] != "api_key" || cfg.Sanitizer.MaxReplacements != 5 {
		t.Fatalf("unexpected sanitizer config: %+v", cfg.Sanitizer)
	}
}

func TestParseYAMLLiteNotificationsConfig(t *testing.T) {
	cfg := Default()
	err := parseYAMLLite(strings.NewReader(`notifications:
  enabled: false
`), &cfg)
	if err != nil {
		t.Fatalf("parseYAMLLite() error = %v", err)
	}
	if cfg.Notifications.Enabled {
		t.Fatalf("expected notifications to be disabled")
	}
}

func TestParseYAMLLiteONNXNERConfig(t *testing.T) {
	cfg := Default()
	err := parseYAMLLite(strings.NewReader(`sanitizer:
  detectors:
    onnx_ner:
      enabled: true
      max_bytes: 4096
      timeout_ms: 25
      min_score: 0.8
`), &cfg)
	if err != nil {
		t.Fatalf("parseYAMLLite() error = %v", err)
	}
	ner := cfg.Sanitizer.Detectors.ONNXNER
	if !ner.Enabled || ner.MaxBytes != 4096 || ner.TimeoutMS != 25 || ner.MinScore != 0.8 {
		t.Fatalf("unexpected onnx_ner config: %+v", ner)
	}
}

func TestParseYAMLLiteSanitizeKeysAndSkipKeys(t *testing.T) {
	cfg := Default()
	err := parseYAMLLite(strings.NewReader(`sanitizer:
  enabled: true
  sanitize_keys:
    - content
    - prompt
    - custom_field
  skip_keys:
    - token
    - access_token
    - session_id
`), &cfg)
	if err != nil {
		t.Fatalf("parseYAMLLite() error = %v", err)
	}
	if len(cfg.Sanitizer.SanitizeKeys) != 3 {
		t.Fatalf("expected 3 sanitize_keys, got %v", cfg.Sanitizer.SanitizeKeys)
	}
	if cfg.Sanitizer.SanitizeKeys[0] != "content" || cfg.Sanitizer.SanitizeKeys[2] != "custom_field" {
		t.Fatalf("unexpected sanitize_keys: %v", cfg.Sanitizer.SanitizeKeys)
	}
	if len(cfg.Sanitizer.SkipKeys) != 3 {
		t.Fatalf("expected 3 skip_keys, got %v", cfg.Sanitizer.SkipKeys)
	}
	if cfg.Sanitizer.SkipKeys[0] != "token" || cfg.Sanitizer.SkipKeys[2] != "session_id" {
		t.Fatalf("unexpected skip_keys: %v", cfg.Sanitizer.SkipKeys)
	}
}

func TestDefaultConfigHasSanitizeKeysAndSkipKeys(t *testing.T) {
	cfg := Default()
	if len(cfg.Sanitizer.SanitizeKeys) == 0 {
		t.Fatal("expected default sanitize_keys to be non-empty")
	}
	if len(cfg.Sanitizer.SkipKeys) == 0 {
		t.Fatal("expected default skip_keys to be non-empty")
	}
}

func TestParseYAMLLiteMITMBodyLoggingConfig(t *testing.T) {
	cfg := Default()
	err := parseYAMLLite(strings.NewReader(`mitm:
  enabled: true
  log_request_response_bodies: false
  log_body_enabled_domains:
    - api.openai.com
    - *.anthropic.com
  log_body_disabled_domains:
    - api.x.ai
`), &cfg)
	if err != nil {
		t.Fatalf("parseYAMLLite() error = %v", err)
	}
	if cfg.MITM.LogRequestResponseBodies {
		t.Fatal("expected log_request_response_bodies to be false")
	}
	if len(cfg.MITM.LogBodyEnabledDomains) != 2 {
		t.Fatalf("unexpected log_body_enabled_domains: %v", cfg.MITM.LogBodyEnabledDomains)
	}
	if len(cfg.MITM.LogBodyDisabledDomains) != 1 || cfg.MITM.LogBodyDisabledDomains[0] != "api.x.ai" {
		t.Fatalf("unexpected log_body_disabled_domains: %v", cfg.MITM.LogBodyDisabledDomains)
	}
}
