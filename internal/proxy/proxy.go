package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"velar/internal/audit"
	"velar/internal/classifier"
	"velar/internal/config"
	"velar/internal/detect"
	"velar/internal/policy"
	"velar/internal/proxy/mitm"
	"velar/internal/sanitizer"
	"velar/internal/trace"
)

type Server interface {
	Start() error
	Shutdown(ctx context.Context) error
}

type Proxy struct {
	httpServer *http.Server
	transport  *http.Transport
	policy     policy.Engine
	classifier classifier.Classifier
	audit      audit.Logger
	inspector  mitm.Inspector
	mitm       *mitm.Handler
	mitmCfg    config.MITM
}

func New(addr string, p policy.Engine, c classifier.Classifier, a audit.Logger, mitmCfg config.MITM, sanitizerCfg config.Sanitizer, notificationCfg config.Notifications) *Proxy {
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
	}
	pr := &Proxy{
		transport:  transport,
		policy:     p,
		classifier: c,
		audit:      a,
		inspector:  mitm.PassthroughInspector{},
		mitmCfg:    mitmCfg,
	}
	inspector := pr.inspector
	if sanitizerCfg.Enabled {
		log.Printf("proxy: initializing SanitizingInspector (notificationsEnabled=%v)", notificationCfg.Enabled)
		detectors := sanitizer.DetectorsByName(sanitizerCfg.Types)
		s := sanitizer.New(detectors).WithConfidenceThreshold(sanitizerCfg.ConfidenceThreshold).WithMaxReplacements(sanitizerCfg.MaxReplacements)
		fast := []detect.Detector{detect.RegexDetector{}}
		onnxCfg := sanitizerCfg.Detectors.ONNXNER
		onnxDetector := detect.NewONNXNERDetector(detect.ONNXNERConfig{MaxBytes: onnxCfg.MaxBytes})

		// Perform health check on ONNX NER if enabled
		if onnxCfg.Enabled {
			log.Printf("proxy: ONNX NER is enabled, performing health check...")
			testCtx, testCancel := context.WithTimeout(context.Background(), 5*time.Second)
			testText := "Test detection for John Smith"
			_, testErr := onnxDetector.Detect(testCtx, testText)
			testCancel()

			if testErr != nil {
				if errors.Is(testErr, detect.ErrNERUnavailable) {
					log.Printf("proxy: warning: ONNX NER unavailable - model not loaded (see messages above)")
					log.Printf("proxy: warning: only regex-based detection (email, phone, API keys) will work")
					log.Printf("proxy: warning: person names and organizations will NOT be detected")
				} else if testErr == context.DeadlineExceeded {
					log.Printf("proxy: warning: ONNX NER health check timed out after 5s")
					log.Printf("proxy: warning: Python onnxruntime may be hanging on import")
					log.Printf("proxy: warning: check: python3 -c 'import onnxruntime'")
				} else {
					log.Printf("proxy: warning: ONNX NER health check failed: %v", testErr)
				}
				log.Printf("proxy: see docs/onnx-ner-troubleshooting.md for help")
			} else {
				log.Printf("proxy: ONNX NER health check passed - detector is working")
			}
		} else {
			log.Printf("proxy: ONNX NER is disabled in configuration")
		}

		hybrid := detect.HybridDetector{
			Fast:   fast,
			Ner:    onnxDetector,
			Config: detect.HybridConfig{NerEnabled: onnxCfg.Enabled, MaxBytes: onnxCfg.MaxBytes, Timeout: time.Duration(onnxCfg.TimeoutMS) * time.Millisecond, MinScore: onnxCfg.MinScore},
		}
		kc := sanitizer.NewKeyConfig(sanitizerCfg.SanitizeKeys, sanitizerCfg.SkipKeys)
		inspector = sanitizer.NewSanitizingInspector(s).WithHybridDetector(hybrid).WithKeyConfig(kc).WithNotifications(notificationCfg.Enabled).WithRestoreResponses(sanitizerCfg.RestoreResponses)
	}
	pr.inspector = inspector

	if mitmCfg.Enabled {
		baseDir, err := mitm.DefaultCAPath()
		if err != nil {
			log.Printf("mitm disabled: cannot resolve CA path: %v", err)
		} else {
			pr.mitm = mitm.NewHandler(mitm.NewCAStore(baseDir), transport, p, c, a, inspector, mitmCfg)
		}
	}
	pr.httpServer = &http.Server{Addr: addr, Handler: http.HandlerFunc(pr.handle)}
	return pr
}

func (p *Proxy) Start() error {
	log.Printf("velar daemon listening on %s", p.httpServer.Addr)
	err := p.httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (p *Proxy) Shutdown(ctx context.Context) error {
	return p.httpServer.Shutdown(ctx)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		log.Printf("request %s took %v", r.URL, time.Since(start))
	}()

	// Health check endpoint
	if r.URL.Path == "/health" {
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.Write([]byte("OK"))
		return
	}

	host := normalizeHost(r.Host)
	if host == "" && r.URL != nil {
		host = normalizeHost(r.URL.Host)
	}

	_ = p.classifier.Classify(host)
	decision := p.policy.Evaluate(host)

	entry := audit.Entry{Method: r.Method, Host: host, Path: r.URL.Path, Decision: string(decision.Decision), Reason: fmt.Sprintf("%s (%s)", decision.Reason, decision.RuleID)}
	defer func() {
		entry.StatusCode = rec.status
		entry.TotalLatencyMs = float64(time.Since(start).Microseconds()) / 1000
		if err := p.audit.Log(entry); err != nil {
			log.Printf("audit log error: %v", err)
		}
	}()

	if decision.Decision == policy.Block {
		http.Error(rec, "blocked by Velar policy", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(rec, r)
		return
	}
	p.handleHTTP(rec, r)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(p)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking not supported")
	}
	return hj.Hijack()
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	requestTrace := trace.NewRequestTrace()
	ctx := trace.WithContext(r.Context(), requestTrace)
	r = r.WithContext(ctx)

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = r.Host
	}
	inspector := p.inspector
	if inspector == nil {
		inspector = mitm.PassthroughInspector{}
	}
	requestTrace.SanitizeStart = time.Now()
	outReq, err := inspector.InspectRequest(outReq)
	if err != nil {
		requestTrace.SanitizeEnd = time.Now()
		http.Error(w, "request inspection failed", http.StatusBadRequest)
		return
	}
	requestTrace.SanitizeEnd = time.Now()

	requestTrace.UpstreamStart = time.Now()
	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	requestTrace.FirstByte = time.Now()
	requestTrace.IsStreaming = isStreaming(resp)
	resp.Body = requestTrace.TrackingReadCloser(resp.Body, func() {
		requestTrace.UpstreamEnd = time.Now()
	})

	requestTrace.ResponseStart = time.Now()
	resp, err = inspector.InspectResponse(resp)
	requestTrace.ResponseEnd = time.Now()
	if err != nil {
		http.Error(w, "response inspection failed", http.StatusBadGateway)
		return
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	_ = resp.Body.Close()
	requestTrace.LogAt(time.Now())
}

func isStreaming(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return true
	}
	for _, v := range resp.TransferEncoding {
		if strings.EqualFold(v, "chunked") {
			return true
		}
	}
	return false
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := connectTarget(r.Host)
	if target == "" {
		http.Error(w, "missing CONNECT target", http.StatusBadRequest)
		return
	}

	host := normalizeHost(target)
	decision := p.policy.Evaluate(host)
	log.Printf("CONNECT %s decision=%s", target, decision.Decision)

	if p.shouldMITM(target, decision) {
		log.Printf("CONNECT request to %s (mode=mitm)", target)
		p.handleMITM(w, r, target)
		return
	}
	log.Printf("CONNECT request to %s (mode=tunnel)", target)
	p.handleTunnel(w, target)
}

func (p *Proxy) handleMITM(w http.ResponseWriter, r *http.Request, target string) {
	log.Printf("handleMITM: starting for %s", target)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("handleMITM: hijack failed for %s: %v", target, err)
		return
	}

	log.Printf("handleMITM: sending 200 Connection Established to %s", target)
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	log.Printf("handleMITM: delegating to MITM handler for %s", target)
	p.mitm.HandleMITM(clientConn, target)
	log.Printf("handleMITM: completed for %s", target)
}

func (p *Proxy) handleTunnel(w http.ResponseWriter, target string) {
	dstConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		http.Error(w, "failed to connect upstream", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = dstConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		_ = dstConn.Close()
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		_ = dstConn.Close()
		return
	}

	go tunnel(dstConn, clientConn)
	tunnel(clientConn, dstConn)
}

func connectTarget(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	if strings.Contains(host, ":") {
		return host
	}
	return net.JoinHostPort(host, "443")
}

func (p *Proxy) shouldMITM(host string, decision policy.Result) bool {
	if p.mitm == nil || !p.mitmCfg.Enabled {
		return false
	}
	if decision.Decision != policy.MITM {
		return false
	}
	if len(p.mitmCfg.Domains) == 0 {
		return true
	}
	needle := strings.ToLower(normalizeHost(host))
	for _, domain := range p.mitmCfg.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if needle == domain || strings.HasSuffix(needle, "."+domain) {
			return true
		}
	}
	return false
}

func tunnel(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func copyHeader(dst, src http.Header) {
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func normalizeHost(hostport string) string {
	if hostport == "" {
		return ""
	}
	if strings.HasPrefix(hostport, "[") {
		h, _, err := net.SplitHostPort(hostport)
		if err == nil {
			return h
		}
	}
	if strings.Contains(hostport, ":") {
		h, _, err := net.SplitHostPort(hostport)
		if err == nil {
			return h
		}
		parts := strings.Split(hostport, ":")
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return hostport
}
