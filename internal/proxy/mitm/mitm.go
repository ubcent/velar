package mitm

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"velar/internal/audit"
	"velar/internal/classifier"
	"velar/internal/config"
	"velar/internal/policy"
	"velar/internal/sanitizer"
	"velar/internal/session"
	"velar/internal/trace"
)

const (
	maxBodySize      = 1 << 20
	maxAuditBodySize = 512
)

type errorLogger struct {
	host string
}

func (el *errorLogger) Write(p []byte) (n int, err error) {
	log.Printf("MITM HTTP server error for %s: %s", el.host, string(p))
	return len(p), nil
}

type Handler struct {
	ca         *CAStore
	transport  *http.Transport
	inspector  Inspector
	policy     policy.Engine
	classifier classifier.Classifier
	audit      audit.Logger
	sessions   *session.Store
	mitmCfg    config.MITM
}

func NewHandler(ca *CAStore, transport *http.Transport, p policy.Engine, cls classifier.Classifier, logger audit.Logger, insp Inspector, mitmCfg config.MITM) *Handler {
	if insp == nil {
		insp = PassthroughInspector{}
	}
	h := &Handler{ca: ca, transport: transport, policy: p, classifier: cls, audit: logger, inspector: insp, sessions: session.NewStore(), mitmCfg: mitmCfg}
	if si, ok := insp.(*sanitizer.SanitizingInspector); ok {
		si.WithSessions(h.sessions)
	}
	return h
}

func (h *Handler) HandleMITM(clientConn net.Conn, host string) {
	log.Printf("MITM: starting for %s", host)
	cert, err := h.ca.GetLeafCert(normalizeHost(host))
	if err != nil {
		log.Printf("MITM: cert error for %s: %v", host, err)
		_ = clientConn.Close()
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err := tlsClient.Handshake(); err != nil {
		log.Printf("MITM: handshake failed for %s: %v", host, err)
		_ = tlsClient.Close()
		return
	}

	srv := &http.Server{
		Handler:           h.serverHandler(host),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(io.Writer(&errorLogger{host: host}), "", 0),
	}
	listener := &singleConnListener{done: make(chan struct{})}
	listener.conn = &notifyCloseConn{Conn: tlsClient, onClose: listener.Close}
	_ = srv.Serve(listener)
	log.Printf("MITM: completed for %s", host)
}

func (h *Handler) serverHandler(connectHost string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			log.Printf("request %s took %v", r.URL, time.Since(start))
		}()
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("MITM handler panic: %v", rec)
			}
		}()
		host := normalizeHost(connectHost)
		requestTrace := trace.NewRequestTrace()
		ctx := trace.WithContext(r.Context(), requestTrace)
		r = r.WithContext(ctx)

		// Generate sessionID early to track this request/response pair
		sessionID := session.GenerateID()

		// Add sessionID to request context
		r = r.WithContext(session.ContextWithID(r.Context(), sessionID))

		_ = h.classifier.Classify(host)
		decision := h.policy.Evaluate(host)
		if decision.Decision == policy.Block {
			http.Error(w, "blocked by Velar policy", http.StatusForbidden)
			h.logAudit(r, host, decision, "", "")
			return
		}

		req, reqPreview, skipInspect, err := cloneLimitedRequest(r, maxBodySize)
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = connectHost
		req.RequestURI = ""
		req.Host = connectHost

		// Remove hop-by-hop headers that shouldn't be forwarded
		req.Header.Del("Connection")
		req.Header.Del("Keep-Alive")
		req.Header.Del("Proxy-Authenticate")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("TE")
		req.Header.Del("Trailers")
		req.Header.Del("Transfer-Encoding")
		req.Header.Del("Upgrade")

		// Ensure User-Agent is set to avoid Cloudflare challenges
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		}

		// Add browser-like headers to bypass Cloudflare challenges
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json, text/plain, */*")
		}
		if req.Header.Get("Accept-Language") == "" {
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		}
		if req.Header.Get("Accept-Encoding") == "" {
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		}
		if req.Header.Get("Referer") == "" {
			req.Header.Set("Referer", "https://"+connectHost+"/")
		}
		if req.Header.Get("Sec-Fetch-Site") == "" {
			req.Header.Set("Sec-Fetch-Site", "same-origin")
		}
		if req.Header.Get("Sec-Fetch-Mode") == "" {
			req.Header.Set("Sec-Fetch-Mode", "cors")
		}
		if req.Header.Get("Sec-Fetch-Dest") == "" {
			req.Header.Set("Sec-Fetch-Dest", "empty")
		}

		requestTrace.SanitizeStart = time.Now()
		if !skipInspect {
			req, err = h.inspector.InspectRequest(req)
			requestTrace.SanitizeEnd = time.Now()
			if err != nil {
				log.Printf("MITM: InspectRequest error: %v", err)
				http.Error(w, "request inspection failed", http.StatusBadRequest)
				return
			}
			if updatedPreview, ok := requestJSONPreview(req); ok {
				reqPreview = updatedPreview
			}
		} else {
			requestTrace.SanitizeEnd = time.Now()
			log.Printf("sanitize skipped body size: %d", r.ContentLength)
		}

		requestTrace.UpstreamStart = time.Now()
		resp, err := h.transport.RoundTrip(req)
		if err != nil {
			log.Printf("MITM: RoundTrip error for %s: %v", host, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if resp.StatusCode == http.StatusForbidden {
			log.Printf("MITM: upstream 403 for %s %s%s (Cf-Mitigated: %s, Server: %s, Content-Type: %s)",
				req.Method, host, req.URL.Path,
				resp.Header.Get("Cf-Mitigated"),
				resp.Header.Get("Server"),
				resp.Header.Get("Content-Type"))
		}
		requestTrace.FirstByte = time.Now()
		requestTrace.IsStreaming = isStreamingResponse(resp)
		resp.Body = requestTrace.TrackingReadCloser(resp.Body, func() {
			requestTrace.UpstreamEnd = time.Now()
		})

		if isStreamingResponse(resp) {
			log.Printf("processing streaming response")
			requestTrace.ResponseStart = time.Now()

			// Inspector will wrap body with StreamingRestorer if needed
			resp, err = h.inspector.InspectResponse(resp)
			if err != nil {
				requestTrace.ResponseEnd = time.Now()
				log.Printf("MITM: streaming response inspection failed: %v", err)
				http.Error(w, "response inspection failed", http.StatusBadGateway)
				return
			}
			requestTrace.ResponseEnd = time.Now()

			copyHeader(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			_ = resp.Body.Close()
			requestTrace.LogAt(time.Now())
			h.logAudit(req, host, decision, reqPreview, "")
			return
		}

		if resp.ContentLength > maxBodySize || resp.ContentLength < 0 {
			log.Printf("response processing skipped body size: %d", resp.ContentLength)
			copyHeader(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			_ = resp.Body.Close()
			requestTrace.LogAt(time.Now())
			h.logAudit(req, host, decision, reqPreview, "")
			return
		}

		requestTrace.ResponseStart = time.Now()
		resp, respPreview, err := cloneLimitedResponse(resp, maxBodySize)
		if err != nil {
			http.Error(w, "upstream body too large", http.StatusBadGateway)
			return
		}
		resp, err = h.inspector.InspectResponse(resp)
		if err != nil {
			requestTrace.ResponseEnd = time.Now()
			http.Error(w, "response inspection failed", http.StatusBadGateway)
			return
		}

		// Restore response if we have a mapping for this session
		resp = h.restoreResponse(resp, sessionID)
		requestTrace.ResponseEnd = time.Now()
		defer h.sessions.Delete(sessionID)

		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		_ = resp.Body.Close()
		requestTrace.LogAt(time.Now())
		h.logAudit(req, host, decision, reqPreview, respPreview)
	})
}

func (h *Handler) restoreResponse(resp *http.Response, sessionID string) *http.Response {
	if resp == nil || sessionID == "" || h.sessions == nil {
		return resp
	}

	// Skip if no content
	if resp.Body == nil {
		return resp
	}

	// Skip streaming/event-stream content
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/event-stream") {
		return resp
	}

	// Skip non-text content types
	if !isTextContentType(contentType) {
		return resp
	}

	// Skip compressed responses — cannot do text replacement on encoded content
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		return resp
	}

	// Check content length
	limit := int64(maxBodySize)
	if resp.ContentLength > limit || resp.ContentLength < 0 {
		return resp
	}

	// Get the session mapping
	sess, ok := h.sessions.Get(sessionID)
	if !ok || len(sess.Mapping) == 0 {
		return resp
	}

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp
	}

	if int64(len(body)) > limit {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp
	}

	// Apply restoration
	restored := string(body)
	for placeholder, original := range sess.Mapping {
		if strings.Contains(restored, placeholder) {
			restored = strings.ReplaceAll(restored, placeholder, original)
		}
	}

	// Update response body and headers
	newBody := []byte(restored)
	resp.Body = io.NopCloser(bytes.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	resp.Header.Del("Transfer-Encoding")

	return resp
}

func (h *Handler) logAudit(r *http.Request, host string, decision policy.Result, reqPreview, respPreview string) {
	if h.audit == nil {
		return
	}
	if !h.shouldLogBody(host) {
		reqPreview = ""
		respPreview = ""
	}
	entry := audit.Entry{Method: r.Method, Host: host, Path: r.URL.Path, Decision: string(decision.Decision), Reason: fmt.Sprintf("%s (%s)", decision.Reason, decision.RuleID), RequestBodyPreview: reqPreview, ResponseBodyPreview: respPreview}
	if md, ok := sanitizer.AuditMetadataFromRequest(r); ok && md.Sanitized {
		entry.Sanitized = true
		entry.SanitizedItems = make([]audit.SanitizedAudit, 0, len(md.Items))
		for _, item := range md.Items {
			entry.SanitizedItems = append(entry.SanitizedItems, audit.SanitizedAudit{Type: item.Type, Placeholder: item.Placeholder})
		}
	}
	_ = h.audit.Log(entry)
}

func (h *Handler) shouldLogBody(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, pattern := range h.mitmCfg.LogBodyDisabledDomains {
		if domainMatches(host, pattern) {
			return false
		}
	}
	for _, pattern := range h.mitmCfg.LogBodyEnabledDomains {
		if domainMatches(host, pattern) {
			return true
		}
	}
	return h.mitmCfg.LogRequestResponseBodies
}

func domainMatches(host, pattern string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	pattern = strings.Trim(strings.ToLower(strings.TrimSpace(pattern)), ".")
	if host == "" || pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		pattern = strings.TrimPrefix(pattern, "*.")
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

func isStreamingResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(contentType, "text/event-stream")
}

func requestJSONPreview(r *http.Request) (string, bool) {
	if r.Body == nil {
		return "", false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return "", false
	}
	preview := string(body)
	if len(preview) > maxAuditBodySize {
		preview = preview[:maxAuditBodySize]
	}
	preview = strings.ReplaceAll(preview, "\n", "")
	return preview, true
}

func cloneLimitedRequest(r *http.Request, limit int64) (*http.Request, string, bool, error) {
	out := r.Clone(r.Context())
	if r.Body == nil {
		return out, "", false, nil
	}
	if r.ContentLength > limit || r.ContentLength < 0 {
		out.Body = r.Body
		out.ContentLength = r.ContentLength
		return out, "", true, nil
	}
	body, preview, err := readLimitedBody(r.Body, r.Header.Get("Content-Type"), limit)
	if err != nil {
		return nil, "", false, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	return out, preview, false, nil
}

func cloneLimitedResponse(r *http.Response, limit int64) (*http.Response, string, error) {
	if r.Body == nil {
		return r, "", nil
	}
	body, preview, err := readLimitedBody(r.Body, r.Header.Get("Content-Type"), limit)
	if err != nil {
		return nil, "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return r, preview, nil
}

func readLimitedBody(rc io.ReadCloser, contentType string, limit int64) ([]byte, string, error) {
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > limit {
		return nil, "", fmt.Errorf("body exceeds limit")
	}
	if !strings.Contains(strings.ToLower(contentType), "application/json") {
		return body, "", nil
	}
	preview := string(body)
	if len(preview) > maxAuditBodySize {
		preview = preview[:maxAuditBodySize]
	}
	preview = strings.ReplaceAll(preview, "\n", "")
	return body, preview, nil
}

type singleConnListener struct {
	mu       sync.Mutex
	conn     net.Conn
	accepted bool
	done     chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.accepted {
		l.mu.Unlock()
		// Block until the connection is closed instead of returning
		// io.EOF immediately. If we return io.EOF, http.Server.Serve
		// exits and calls srv.Close() which kills the goroutine that
		// is serving keep-alive requests on the accepted connection.
		<-l.done
		return nil, io.EOF
	}
	l.accepted = true
	c := l.conn
	l.mu.Unlock()
	return c, nil
}
func (l *singleConnListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}
func (l *singleConnListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

// notifyCloseConn wraps a net.Conn and calls onClose when Close is called.
// When http.Server closes the connection (idle timeout, client disconnect),
// this triggers listener.Close() which unblocks Accept() and lets Serve return.
type notifyCloseConn struct {
	net.Conn
	closeOnce sync.Once
	onClose   func() error
}

func (c *notifyCloseConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			_ = c.onClose()
		}
	})
	return err
}

func normalizeHost(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err == nil {
		return host
	}
	return hostport
}

func copyHeader(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func HandleMITM(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "standalone MITM handler is not wired", http.StatusNotImplemented)
}

func isTextContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "text/plain") ||
		strings.Contains(ct, "application/x-www-form-urlencoded") ||
		strings.Contains(ct, "text/")
}
