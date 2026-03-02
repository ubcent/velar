package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	defaultPort    = 8080
	defaultLogFile = "~/.velar/audit.log"
)

type Match struct {
	Host         string `json:"host"`
	HostContains string `json:"host_contains"`
}

type Rule struct {
	ID     string `json:"id"`
	Match  Match  `json:"match"`
	Action string `json:"action"`
}

type Config struct {
	Port          int           `json:"port"`
	LogFile       string        `json:"log_file"`
	MITM          MITM          `json:"mitm"`
	Sanitizer     Sanitizer     `json:"sanitizer"`
	Notifications Notifications `json:"notifications"`
	Rules         []Rule        `json:"rules"`
}

type MITM struct {
	Enabled                  bool     `json:"enabled"`
	Domains                  []string `json:"domains"`
	LogRequestResponseBodies bool     `json:"log_request_response_bodies"`
	LogBodyEnabledDomains    []string `json:"log_body_enabled_domains"`
	LogBodyDisabledDomains   []string `json:"log_body_disabled_domains"`
}

type Sanitizer struct {
	Enabled             bool      `json:"enabled"`
	Types               []string  `json:"types"`
	ConfidenceThreshold float64   `json:"confidence_threshold"`
	MaxReplacements     int       `json:"max_replacements"`
	RestoreResponses    bool      `json:"restore_responses"`
	SanitizeKeys        []string  `json:"sanitize_keys"`
	SkipKeys            []string  `json:"skip_keys"`
	Detectors           Detectors `json:"detectors"`
}

type Detectors struct {
	ONNXNER ONNXNER `json:"onnx_ner"`
}

type ONNXNER struct {
	Enabled   bool    `json:"enabled"`
	MaxBytes  int     `json:"max_bytes"`
	TimeoutMS int     `json:"timeout_ms"`
	MinScore  float64 `json:"min_score"`
}

type Notifications struct {
	Enabled bool `json:"enabled"`
}

func Default() Config {
	return Config{
		Port:    defaultPort,
		LogFile: defaultLogFile,
		MITM: MITM{
			LogRequestResponseBodies: true,
		},
		Sanitizer: Sanitizer{
			Types:            []string{"email", "phone", "api_key", "jwt", "aws_access_key", "aws_secret_key", "aws_session_token", "gcp_api_key", "gcp_service_account", "azure_connection_string", "azure_sas_token", "private_key", "db_url", "high_entropy", "hex_secret"},
			RestoreResponses: true,
			SanitizeKeys:     []string{"prompt", "input", "content", "text", "message", "parts"},
			SkipKeys:         []string{"authorization", "access_token", "session_token", "token", "bearer", "id_token", "refresh_token", "api_key", "apikey", "x-api-key", "cookie", "set-cookie", "model", "role", "type", "id", "object", "created", "system_fingerprint"},
			Detectors:        Detectors{ONNXNER: ONNXNER{Enabled: false, MaxBytes: 32 * 1024, TimeoutMS: 5000, MinScore: 0.70}},
		},
		Notifications: Notifications{Enabled: true},
		Rules: []Rule{{
			ID:     "allow_all",
			Action: "allow",
		}},
	}
}

func ConfigPath() (string, error) {
	appDir, err := AppDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(appDir, "config.yaml"), nil
}

var legacyConfigWarnOnce sync.Once

func AppDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	velarDir := filepath.Join(home, ".velar")
	legacyDir := filepath.Join(home, ".promptshield")

	if !pathExists(velarDir) && pathExists(legacyDir) {
		legacyConfigWarnOnce.Do(func() {
			log.Printf("Deprecated config path ~/.promptshield detected, please migrate to ~/.velar")
		})
		return legacyDir, nil
	}

	return velarDir, nil
}

func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg.LogFile = expandHome(cfg.LogFile)
			applyEnvOverrides(&cfg)
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	if err := parseConfig(data, &cfg); err != nil {
		return Config{}, err
	}

	cfg.LogFile = expandHome(cfg.LogFile)
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.LogFile == "" {
		cfg.LogFile = expandHome(defaultLogFile)
	}
	if len(cfg.Rules) == 0 {
		cfg.Rules = Default().Rules
	}

	applyEnvOverrides(&cfg)

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v, ok := envString("VELAR_LOG_FILE", "PROMPTSHIELD_LOG_FILE"); ok {
		cfg.LogFile = expandHome(v)
	}
	if v, ok := envInt("VELAR_PORT", "PROMPTSHIELD_PORT"); ok {
		cfg.Port = v
	}
}

func envString(newKey, oldKey string) (string, bool) {
	if v, ok := lookupEnvTrimmed(newKey); ok {
		return v, true
	}
	if v, ok := lookupEnvTrimmed(oldKey); ok {
		log.Printf("Deprecated env var %s detected, please migrate to %s", oldKey, newKey)
		return v, true
	}
	return "", false
}

func envInt(newKey, oldKey string) (int, bool) {
	v, ok := envString(newKey, oldKey)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func lookupEnvTrimmed(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func EnsureConfigDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0o755)
}

func parseConfig(data []byte, cfg *Config) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, cfg); err != nil {
			return fmt.Errorf("parse json config: %w", err)
		}
		return nil
	}
	return parseYAMLLite(strings.NewReader(trimmed), cfg)
}

func parseYAMLLite(r *strings.Reader, cfg *Config) error {
	s := bufio.NewScanner(r)
	var currentRule *Rule
	inMatch := false
	inMITM := false
	inMITMDomains := false
	inMITMLogBodyEnabledDomains := false
	inMITMLogBodyDisabledDomains := false
	inSanitizer := false
	inSanitizerTypes := false
	inSanitizeKeys := false
	inSkipKeys := false
	inNotifications := false
	inDetectors := false
	inONNXNER := false
	rulesFound := false

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimLeft(line, "-")
		line = strings.TrimSpace(line)

		switch {
		case line == "rules:":
			if !rulesFound {
				cfg.Rules = nil
				rulesFound = true
			}
			inSanitizer = false
			inSanitizerTypes = false
			inSanitizeKeys = false
			inSkipKeys = false
			inMITMDomains = false
			inMITM = false
			inNotifications = false
			continue
		case line == "mitm:":
			inSanitizer = false
			inSanitizerTypes = false
			inSanitizeKeys = false
			inSkipKeys = false
			inMITM = true
			inMITMDomains = false
			inMITMLogBodyEnabledDomains = false
			inMITMLogBodyDisabledDomains = false
			inNotifications = false
			continue
		case line == "sanitizer:":
			inMITM = false
			inMITMDomains = false
			inSanitizer = true
			inSanitizerTypes = false
			inSanitizeKeys = false
			inSkipKeys = false
			inNotifications = false
			continue
		case line == "notifications:":
			inMITM = false
			inMITMDomains = false
			inSanitizer = false
			inSanitizerTypes = false
			inSanitizeKeys = false
			inSkipKeys = false
			inNotifications = true
			continue
		case line == "detectors:" && inSanitizer:
			inDetectors = true
			inONNXNER = false
			continue
		case line == "onnx_ner:" && inDetectors:
			inONNXNER = true
			continue
		case line == "domains:" && inMITM:
			inMITMDomains = true
			inMITMLogBodyEnabledDomains = false
			inMITMLogBodyDisabledDomains = false
			continue
		case line == "log_body_enabled_domains:" && inMITM:
			cfg.MITM.LogBodyEnabledDomains = nil
			inMITMDomains = false
			inMITMLogBodyEnabledDomains = true
			inMITMLogBodyDisabledDomains = false
			continue
		case line == "log_body_disabled_domains:" && inMITM:
			cfg.MITM.LogBodyDisabledDomains = nil
			inMITMDomains = false
			inMITMLogBodyEnabledDomains = false
			inMITMLogBodyDisabledDomains = true
			continue
		case line == "types:" && inSanitizer:
			cfg.Sanitizer.Types = nil
			inSanitizerTypes = true
			inSanitizeKeys = false
			inSkipKeys = false
			continue
		case line == "sanitize_keys:" && inSanitizer:
			cfg.Sanitizer.SanitizeKeys = nil
			inSanitizeKeys = true
			inSanitizerTypes = false
			inSkipKeys = false
			continue
		case line == "skip_keys:" && inSanitizer:
			cfg.Sanitizer.SkipKeys = nil
			inSkipKeys = true
			inSanitizerTypes = false
			inSanitizeKeys = false
			continue
		case inMITMDomains && strings.HasPrefix(strings.TrimSpace(s.Text()), "-"):
			domain := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s.Text()), "-"))
			if domain != "" {
				cfg.MITM.Domains = append(cfg.MITM.Domains, domain)
			}
			continue
		case inMITMLogBodyEnabledDomains && strings.HasPrefix(strings.TrimSpace(s.Text()), "-"):
			domain := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s.Text()), "-"))
			if domain != "" {
				cfg.MITM.LogBodyEnabledDomains = append(cfg.MITM.LogBodyEnabledDomains, domain)
			}
			continue
		case inMITMLogBodyDisabledDomains && strings.HasPrefix(strings.TrimSpace(s.Text()), "-"):
			domain := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s.Text()), "-"))
			if domain != "" {
				cfg.MITM.LogBodyDisabledDomains = append(cfg.MITM.LogBodyDisabledDomains, domain)
			}
			continue
		case inSanitizerTypes && strings.HasPrefix(strings.TrimSpace(s.Text()), "-"):
			typ := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s.Text()), "-"))
			if typ != "" {
				cfg.Sanitizer.Types = append(cfg.Sanitizer.Types, typ)
			}
			continue
		case inSanitizeKeys && strings.HasPrefix(strings.TrimSpace(s.Text()), "-"):
			k := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s.Text()), "-"))
			if k != "" {
				cfg.Sanitizer.SanitizeKeys = append(cfg.Sanitizer.SanitizeKeys, k)
			}
			continue
		case inSkipKeys && strings.HasPrefix(strings.TrimSpace(s.Text()), "-"):
			k := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(s.Text()), "-"))
			if k != "" {
				cfg.Sanitizer.SkipKeys = append(cfg.Sanitizer.SkipKeys, k)
			}
			continue
		case strings.HasPrefix(line, "port:"):
			inMITMDomains = false
			inSanitizerTypes = false
			inSanitizeKeys = false
			inSkipKeys = false
			v := strings.TrimSpace(strings.TrimPrefix(line, "port:"))
			port, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid port: %s", v)
			}
			cfg.Port = port
		case strings.HasPrefix(line, "log_file:"):
			inMITMDomains = false
			inSanitizerTypes = false
			inSanitizeKeys = false
			inSkipKeys = false
			cfg.LogFile = strings.TrimSpace(strings.TrimPrefix(line, "log_file:"))
		case strings.HasPrefix(line, "enabled:") && inMITM:
			inMITMDomains = false
			inMITMLogBodyEnabledDomains = false
			inMITMLogBodyDisabledDomains = false
			cfg.MITM.Enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "enabled:")), "true")
		case strings.HasPrefix(line, "log_request_response_bodies:") && inMITM:
			cfg.MITM.LogRequestResponseBodies = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "log_request_response_bodies:")), "true")
		case strings.HasPrefix(line, "enabled:") && inONNXNER:
			cfg.Sanitizer.Detectors.ONNXNER.Enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "enabled:")), "true")
		case strings.HasPrefix(line, "enabled:") && inSanitizer:
			cfg.Sanitizer.Enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "enabled:")), "true")
		case strings.HasPrefix(line, "enabled:") && inNotifications:
			cfg.Notifications.Enabled = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "enabled:")), "true")
		case strings.HasPrefix(line, "confidence_threshold:") && inSanitizer:
			v := strings.TrimSpace(strings.TrimPrefix(line, "confidence_threshold:"))
			threshold, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return fmt.Errorf("invalid confidence_threshold: %s", v)
			}
			cfg.Sanitizer.ConfidenceThreshold = threshold
		case strings.HasPrefix(line, "max_replacements:") && inSanitizer:
			v := strings.TrimSpace(strings.TrimPrefix(line, "max_replacements:"))
			maxRepl, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid max_replacements: %s", v)
			}
			cfg.Sanitizer.MaxReplacements = maxRepl
		case strings.HasPrefix(line, "restore_responses:") && inSanitizer:
			cfg.Sanitizer.RestoreResponses = strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "restore_responses:")), "true")
		case strings.HasPrefix(line, "max_bytes:") && inONNXNER:
			v := strings.TrimSpace(strings.TrimPrefix(line, "max_bytes:"))
			maxBytes, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid max_bytes: %s", v)
			}
			cfg.Sanitizer.Detectors.ONNXNER.MaxBytes = maxBytes
		case strings.HasPrefix(line, "timeout_ms:") && inONNXNER:
			v := strings.TrimSpace(strings.TrimPrefix(line, "timeout_ms:"))
			timeoutMS, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid timeout_ms: %s", v)
			}
			cfg.Sanitizer.Detectors.ONNXNER.TimeoutMS = timeoutMS
		case strings.HasPrefix(line, "min_score:") && inONNXNER:
			v := strings.TrimSpace(strings.TrimPrefix(line, "min_score:"))
			minScore, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return fmt.Errorf("invalid min_score: %s", v)
			}
			cfg.Sanitizer.Detectors.ONNXNER.MinScore = minScore
		case strings.HasPrefix(line, "id:"):
			inMITMDomains = false
			inSanitizer = false
			inSanitizerTypes = false
			inMITM = false
			cfg.Rules = append(cfg.Rules, Rule{})
			currentRule = &cfg.Rules[len(cfg.Rules)-1]
			currentRule.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			inMatch = false
		case strings.HasPrefix(line, "action:"):
			if currentRule == nil {
				cfg.Rules = append(cfg.Rules, Rule{})
				currentRule = &cfg.Rules[len(cfg.Rules)-1]
			}
			currentRule.Action = strings.TrimSpace(strings.TrimPrefix(line, "action:"))
		case line == "match:":
			inMatch = true
		case strings.HasPrefix(line, "host_contains:") && inMatch && currentRule != nil:
			currentRule.Match.HostContains = strings.TrimSpace(strings.TrimPrefix(line, "host_contains:"))
		case strings.HasPrefix(line, "host:") && inMatch && currentRule != nil:
			currentRule.Match.Host = strings.TrimSpace(strings.TrimPrefix(line, "host:"))
		}
	}

	if err := s.Err(); err != nil {
		return fmt.Errorf("scan config: %w", err)
	}
	return nil
}

func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}
