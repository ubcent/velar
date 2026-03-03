package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"velar/internal/audit"
	"velar/internal/classifier"
	"velar/internal/config"
	"velar/internal/policy"
	"velar/internal/proxy/mitm"
	"velar/internal/sanitizer"
)

type memoryAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (m *memoryAudit) Log(e audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}

func (m *memoryAudit) all() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]audit.Entry, len(m.entries))
	copy(out, m.entries)
	return out
}

func newTestProxy(t *testing.T, p policy.Engine, logger audit.Logger, mitmCfg config.MITM, sanitizerCfg config.Sanitizer, caDir string) (*Proxy, *httptest.Server) {
	t.Helper()
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	pr := &Proxy{transport: transport, policy: p, classifier: classifier.HostClassifier{}, audit: logger, mitmCfg: mitmCfg}
	if mitmCfg.Enabled {
		inspector := mitm.Inspector(mitm.PassthroughInspector{})
		if sanitizerCfg.Enabled {
			s := sanitizer.New(sanitizer.DetectorsByName(sanitizerCfg.Types))
			inspector = sanitizer.NewSanitizingInspector(s)
		}
		pr.mitm = mitm.NewHandler(mitm.NewCAStore(caDir), transport, p, classifier.HostClassifier{}, logger, inspector, mitmCfg)
	}
	server := httptest.NewServer(http.HandlerFunc(pr.handle))
	return pr, server
}

func proxyClient(proxyURL string, rootCAs *x509.CertPool) *http.Client {
	proxyParsed, _ := url.Parse(proxyURL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyParsed)}
	if rootCAs != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	}
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func TestProxyAllowScenario(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	auditLog := &memoryAudit{}
	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(nil), auditLog, config.MITM{}, config.Sanitizer{}, t.TempDir())
	defer proxySrv.Close()

	client := proxyClient(proxySrv.URL, nil)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, upstream.URL+"/allow", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK || string(body) != "ok" || upstreamCalls.Load() != 1 || len(auditLog.all()) == 0 {
		t.Fatalf("allow flow validation failed: status=%d body=%q upstream=%d audit=%d", resp.StatusCode, body, upstreamCalls.Load(), len(auditLog.all()))
	}
}

func TestProxyBlockScenario(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rules := []config.Rule{{ID: "block-target", Match: config.Match{HostContains: "127.0.0.1"}, Action: "block"}}
	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(rules), &memoryAudit{}, config.MITM{}, config.Sanitizer{}, t.TempDir())
	defer proxySrv.Close()

	resp, err := proxyClient(proxySrv.URL, nil).Get(upstream.URL + "/blocked")
	if err != nil {
		t.Fatalf("client.Get() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden || upstreamCalls.Load() != 0 {
		t.Fatalf("block flow validation failed: status=%d upstream=%d", resp.StatusCode, upstreamCalls.Load())
	}
}

func TestProxyShouldMITMDecision(t *testing.T) {
	pr, _ := newTestProxy(t, policy.NewRuleEngine(nil), &memoryAudit{}, config.MITM{Enabled: true, Domains: []string{"localhost"}}, config.Sanitizer{}, t.TempDir())
	if !pr.shouldMITM("localhost:443", policy.Result{Decision: policy.MITM}) {
		t.Fatalf("expected MITM for configured domain")
	}
	if pr.shouldMITM("example.com:443", policy.Result{Decision: policy.MITM}) {
		t.Fatalf("did not expect MITM for non-configured domain")
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "api.openai.com:443", want: "api.openai.com"},
		{input: "api.openai.com", want: "api.openai.com"},
		{input: "[::1]:8443", want: "::1"},
	}
	for _, tc := range tests {
		if got := normalizeHost(tc.input); got != tc.want {
			t.Fatalf("normalizeHost(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestProxyConnectReturnsEstablishedInsteadOfRedirect(t *testing.T) {
	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(nil), &memoryAudit{}, config.MITM{}, config.Sanitizer{}, t.TempDir())
	defer proxySrv.Close()

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	proxyAddr := strings.TrimPrefix(proxySrv.URL, "http://")
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("CONNECT " + upstream.Addr().String() + " HTTP/1.1\r\nHost: " + upstream.Addr().String() + "\r\n\r\n")); err != nil {
		t.Fatalf("write connect request: %v", err)
	}

	statusLine, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected CONNECT 200, got %q", strings.TrimSpace(statusLine))
	}
}

func TestProxyAuditLoggingJSON(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("audit"))
	}))
	defer upstream.Close()

	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.NewJSONLLogger(logPath)
	if err != nil {
		t.Fatalf("NewJSONLLogger() error = %v", err)
	}
	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(nil), logger, config.MITM{}, config.Sanitizer{}, t.TempDir())
	defer proxySrv.Close()

	resp, err := proxyClient(proxySrv.URL, nil).Get(upstream.URL + "/audit")
	if err != nil {
		t.Fatalf("client.Get() error = %v", err)
	}
	resp.Body.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var entry audit.Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("audit log is not valid json: %v", err)
	}
	if entry.Decision != string(policy.Allow) || entry.Method != http.MethodGet {
		t.Fatalf("unexpected audit entry: %+v", entry)
	}
}

// TestMaskAndRestore verifies that PII is masked upstream and restored in the client response
func TestMaskAndRestore(t *testing.T) {
	// Echo server that captures and returns what it received
	var upstreamReceived string
	var mu sync.Mutex
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		upstreamReceived = string(body)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer echoServer.Close()

	// Setup proxy with MITM and sanitization
	caDir := t.TempDir()
	ca := mitm.NewCAStore(caDir)
	if err := ca.EnsureRootCA(); err != nil {
		t.Fatalf("ensure CA: %v", err)
	}

	mitmCfg := config.MITM{
		Enabled: true,
		Domains: []string{"127.0.0.1"},
	}
	sanitizerCfg := config.Sanitizer{
		Enabled: true,
		Types:   []string{"email"},
	}

	rules := []config.Rule{{ID: "mitm-all", Match: config.Match{HostContains: "127.0.0.1"}, Action: "mitm"}}
	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(rules), &memoryAudit{}, mitmCfg, sanitizerCfg, caDir)
	defer proxySrv.Close()

	// Load CA cert for client
	certPEM, err := os.ReadFile(filepath.Join(caDir, "cert.pem"))
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(certPEM) {
		t.Fatalf("failed to add CA cert to pool")
	}

	// Create HTTPS test server
	httpsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		upstreamReceived = string(body)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	httpsServer.StartTLS()
	defer httpsServer.Close()

	// Create proxy client
	client := proxyClient(proxySrv.URL, rootCAs)
	client.Timeout = 10 * time.Second

	// Send request with email
	original := map[string]string{"message": "my email is dvbondarchuk@gmail.com"}
	reqBody, _ := json.Marshal(original)

	req, err := http.NewRequest(http.MethodPost, httpsServer.URL, strings.NewReader(string(reqBody)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// ASSERT: response contains original email (restored)
	if !strings.Contains(string(respBody), "dvbondarchuk@gmail.com") {
		t.Errorf("response should contain original email, got: %s", string(respBody))
	}

	// ASSERT: response does NOT contain placeholder
	if strings.Contains(string(respBody), "[EMAIL_1]") {
		t.Errorf("response should not contain placeholder, got: %s", string(respBody))
	}

	// ASSERT: upstream received masked value
	mu.Lock()
	received := upstreamReceived
	mu.Unlock()

	if !strings.Contains(received, "[EMAIL_1]") {
		t.Errorf("upstream should receive masked email, got: %s", received)
	}

	if strings.Contains(received, "dvbondarchuk@gmail.com") {
		t.Errorf("upstream should not receive original email, got: %s", received)
	}
}

// TestNoPII verifies that requests without PII pass through unchanged
func TestNoPII(t *testing.T) {
	var upstreamReceived string
	var mu sync.Mutex

	httpsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		upstreamReceived = string(body)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	httpsServer.StartTLS()
	defer httpsServer.Close()

	caDir := t.TempDir()
	ca := mitm.NewCAStore(caDir)
	if err := ca.EnsureRootCA(); err != nil {
		t.Fatalf("ensure CA: %v", err)
	}

	mitmCfg := config.MITM{Enabled: true, Domains: []string{"127.0.0.1"}}
	sanitizerCfg := config.Sanitizer{Enabled: true, Types: []string{"email"}}
	rules := []config.Rule{{ID: "mitm-all", Match: config.Match{HostContains: "127.0.0.1"}, Action: "mitm"}}

	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(rules), &memoryAudit{}, mitmCfg, sanitizerCfg, caDir)
	defer proxySrv.Close()

	certPEM, _ := os.ReadFile(filepath.Join(caDir, "cert.pem"))
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(certPEM)

	client := proxyClient(proxySrv.URL, rootCAs)
	client.Timeout = 10 * time.Second

	original := map[string]string{"message": "hello world no sensitive data"}
	reqBody, _ := json.Marshal(original)

	req, _ := http.NewRequest(http.MethodPost, httpsServer.URL, strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// ASSERT: response unchanged
	if !strings.Contains(string(respBody), "hello world no sensitive data") {
		t.Errorf("response should be unchanged, got: %s", string(respBody))
	}

	// ASSERT: upstream received unchanged
	mu.Lock()
	received := upstreamReceived
	mu.Unlock()

	if !strings.Contains(received, "hello world no sensitive data") {
		t.Errorf("upstream should receive unchanged body, got: %s", received)
	}
}

// TestMultiplePII verifies that multiple PII items are masked and restored correctly
func TestMultiplePII(t *testing.T) {
	var upstreamReceived string
	var mu sync.Mutex

	httpsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		upstreamReceived = string(body)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	httpsServer.StartTLS()
	defer httpsServer.Close()

	caDir := t.TempDir()
	ca := mitm.NewCAStore(caDir)
	if err := ca.EnsureRootCA(); err != nil {
		t.Fatalf("ensure CA: %v", err)
	}

	mitmCfg := config.MITM{Enabled: true, Domains: []string{"127.0.0.1"}}
	sanitizerCfg := config.Sanitizer{Enabled: true, Types: []string{"email"}}
	rules := []config.Rule{{ID: "mitm-all", Match: config.Match{HostContains: "127.0.0.1"}, Action: "mitm"}}

	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(rules), &memoryAudit{}, mitmCfg, sanitizerCfg, caDir)
	defer proxySrv.Close()

	certPEM, _ := os.ReadFile(filepath.Join(caDir, "cert.pem"))
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(certPEM)

	client := proxyClient(proxySrv.URL, rootCAs)
	client.Timeout = 10 * time.Second

	original := map[string]string{"message": "emails: alice@example.com and bob@example.com"}
	reqBody, _ := json.Marshal(original)

	req, _ := http.NewRequest(http.MethodPost, httpsServer.URL, strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// ASSERT: response contains both original emails
	if !strings.Contains(string(respBody), "alice@example.com") {
		t.Errorf("response should contain alice@example.com, got: %s", string(respBody))
	}
	if !strings.Contains(string(respBody), "bob@example.com") {
		t.Errorf("response should contain bob@example.com, got: %s", string(respBody))
	}

	// ASSERT: response does NOT contain placeholders
	if strings.Contains(string(respBody), "[EMAIL_1]") || strings.Contains(string(respBody), "[EMAIL_2]") {
		t.Errorf("response should not contain placeholders, got: %s", string(respBody))
	}

	// ASSERT: upstream received both masked values
	mu.Lock()
	received := upstreamReceived
	mu.Unlock()

	if !strings.Contains(received, "[EMAIL_1]") || !strings.Contains(received, "[EMAIL_2]") {
		t.Errorf("upstream should receive both masked emails, got: %s", received)
	}
}

// TestLargeBodySkipped verifies that large payloads skip sanitization
func TestLargeBodySkipped(t *testing.T) {
	var upstreamReceived string
	var mu sync.Mutex

	httpsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		upstreamReceived = string(body)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	httpsServer.StartTLS()
	defer httpsServer.Close()

	caDir := t.TempDir()
	ca := mitm.NewCAStore(caDir)
	if err := ca.EnsureRootCA(); err != nil {
		t.Fatalf("ensure CA: %v", err)
	}

	mitmCfg := config.MITM{Enabled: true, Domains: []string{"127.0.0.1"}}
	sanitizerCfg := config.Sanitizer{Enabled: true, Types: []string{"email"}}
	rules := []config.Rule{{ID: "mitm-all", Match: config.Match{HostContains: "127.0.0.1"}, Action: "mitm"}}

	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(rules), &memoryAudit{}, mitmCfg, sanitizerCfg, caDir)
	defer proxySrv.Close()

	certPEM, _ := os.ReadFile(filepath.Join(caDir, "cert.pem"))
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(certPEM)

	client := proxyClient(proxySrv.URL, rootCAs)
	client.Timeout = 10 * time.Second

	// Create a large payload (>1MB)
	largeData := strings.Repeat("x", (1<<20)+1024)
	original := map[string]string{"message": "large payload " + largeData + " tail@example.com"}
	reqBody, _ := json.Marshal(original)

	req, _ := http.NewRequest(http.MethodPost, httpsServer.URL, strings.NewReader(string(reqBody)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// ASSERT: response contains original email (not masked due to size)
	if !strings.Contains(string(respBody), "tail@example.com") {
		t.Errorf("response should contain original email when sanitization skipped, got body length: %d", len(respBody))
	}

	// ASSERT: upstream received original email (not masked)
	mu.Lock()
	received := upstreamReceived
	mu.Unlock()

	if !strings.Contains(received, "tail@example.com") {
		t.Errorf("upstream should receive original email for large body, got length: %d", len(received))
	}
}

// TestConcurrentRequests verifies that concurrent requests maintain isolated state
func TestConcurrentRequests(t *testing.T) {
	httpsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	httpsServer.StartTLS()
	defer httpsServer.Close()

	caDir := t.TempDir()
	ca := mitm.NewCAStore(caDir)
	if err := ca.EnsureRootCA(); err != nil {
		t.Fatalf("ensure CA: %v", err)
	}

	mitmCfg := config.MITM{Enabled: true, Domains: []string{"127.0.0.1"}}
	sanitizerCfg := config.Sanitizer{Enabled: true, Types: []string{"email"}}
	rules := []config.Rule{{ID: "mitm-all", Match: config.Match{HostContains: "127.0.0.1"}, Action: "mitm"}}

	_, proxySrv := newTestProxy(t, policy.NewRuleEngine(rules), &memoryAudit{}, mitmCfg, sanitizerCfg, caDir)
	defer proxySrv.Close()

	certPEM, _ := os.ReadFile(filepath.Join(caDir, "cert.pem"))
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(certPEM)

	client := proxyClient(proxySrv.URL, rootCAs)
	client.Timeout = 10 * time.Second

	const workers = 10
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()

			email := "user-" + strings.Repeat("0", 3-len(strings.Split(strings.TrimSpace(strings.Repeat(" ", i)), " "))) + string('0'+rune(i)) + "@example.com"
			if i >= 10 {
				email = "user-" + string('0'+rune(i/10)) + string('0'+rune(i%10)) + "@example.com"
			}

			original := map[string]string{"message": "email: " + email}
			reqBody, _ := json.Marshal(original)

			req, _ := http.NewRequest(http.MethodPost, httpsServer.URL, strings.NewReader(string(reqBody)))
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				errCh <- err
				return
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(resp.Body)

			// ASSERT: response contains correct original email
			if !strings.Contains(string(respBody), email) {
				errCh <- http.ErrMissingFile // placeholder error
				return
			}

			// ASSERT: response does NOT contain placeholder
			if strings.Contains(string(respBody), "[EMAIL_") {
				errCh <- http.ErrBodyNotAllowed // placeholder error
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent request error: %v", err)
	}
}
