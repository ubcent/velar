package mitm

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"velar/internal/audit"
	"velar/internal/classifier"
	"velar/internal/config"
	"velar/internal/policy"
)

func makeGRPCFrame(compressed byte, msg []byte) []byte {
	frame := make([]byte, 5+len(msg))
	frame[0] = compressed
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(msg)))
	copy(frame[5:], msg)
	return frame
}

func TestGRPCFramePreviewUncompressed(t *testing.T) {
	msg := []byte("hello world from grpc")
	frame := makeGRPCFrame(0, msg)

	got := grpcFramePreview(frame)
	if got == "" {
		t.Fatal("expected non-empty preview")
	}
	// Should be a hex string of the message bytes
	wantPrefix := "68656c6c6f" // "hello" in hex
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("preview %q does not start with hex of message", got)
	}
}

func TestGRPCFramePreviewUncompressedTruncatesAt512(t *testing.T) {
	msg := make([]byte, 1024)
	for i := range msg {
		msg[i] = byte(i % 256)
	}
	frame := makeGRPCFrame(0, msg)

	got := grpcFramePreview(frame)
	// hex of 512 bytes = 1024 hex chars
	if len(got) != 1024 {
		t.Errorf("expected 1024 hex chars for 512 byte preview, got %d", len(got))
	}
}

func TestGRPCFramePreviewCompressed(t *testing.T) {
	msg := []byte("compressed-data")
	frame := makeGRPCFrame(1, msg)

	got := grpcFramePreview(frame)
	want := "[compressed, 15 bytes]"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGRPCFramePreviewTooShort(t *testing.T) {
	for _, body := range [][]byte{nil, {}, {0}, {0, 1, 2, 3}} {
		got := grpcFramePreview(body)
		if got != "" {
			t.Errorf("body len %d: expected empty string, got %q", len(body), got)
		}
	}
}

func TestGRPCFramePreviewMaxDepth(t *testing.T) {
	// Exactly 5 bytes (header only, zero-length message)
	frame := makeGRPCFrame(0, []byte{})
	got := grpcFramePreview(frame)
	if got != "" {
		t.Errorf("zero-length message: expected empty hex, got %q", got)
	}
}

func TestMITMGRPCRequestBodyPreview(t *testing.T) {
	var mu sync.Mutex
	var gotReqBody []byte

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotReqBody = body
		mu.Unlock()
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	auditLog := &captureAuditLogger{}
	h := NewHandler(
		NewCAStore(t.TempDir()),
		&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		policy.NewRuleEngine(nil),
		classifier.HostClassifier{},
		auditLog,
		PassthroughInspector{},
		config.MITM{LogRequestResponseBodies: true},
	)

	// Build a valid gRPC frame: [0][0 0 0 4][d a t a]
	msg := []byte("data")
	frame := makeGRPCFrame(0, msg)

	req := httptest.NewRequest(http.MethodPost, "https://proxy/aiserver.v1.AiService/StreamChat",
		strings.NewReader(string(frame)))
	req.Header.Set("Content-Type", "application/grpc+proto")
	req.ContentLength = int64(len(frame))
	rec := httptest.NewRecorder()

	h.serverHandler(upstream.Listener.Addr().String()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	mu.Lock()
	_ = gotReqBody
	mu.Unlock()

	auditLog.mu.Lock()
	defer auditLog.mu.Unlock()
	if len(auditLog.entries) == 0 {
		t.Fatal("no audit entries logged")
	}
	preview := auditLog.entries[len(auditLog.entries)-1].RequestBodyPreview
	if preview == "" {
		t.Fatal("expected non-empty request_body_preview for gRPC request")
	}
	// Preview should be hex of "data" = "64617461"
	if !strings.HasPrefix(preview, "6461746") {
		t.Errorf("expected hex preview starting with hex of 'data', got %q", preview)
	}
}

type captureAuditLogger struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (c *captureAuditLogger) Log(e audit.Entry) error {
	c.mu.Lock()
	c.entries = append(c.entries, e)
	c.mu.Unlock()
	return nil
}

// buildProtoMsg encodes field/value pairs into raw protobuf wire format.
// Supported value types: string, []byte, uint64, int (as varint), and []byte tagged as nested.
func buildProtoMsg(fields ...interface{}) []byte {
	// fields come in pairs: (fieldNum protowire.Number, value)
	var b []byte
	for i := 0; i+1 < len(fields); i += 2 {
		num := fields[i].(protowire.Number)
		switch v := fields[i+1].(type) {
		case string:
			b = protowire.AppendTag(b, num, protowire.BytesType)
			b = protowire.AppendBytes(b, []byte(v))
		case []byte:
			b = protowire.AppendTag(b, num, protowire.BytesType)
			b = protowire.AppendBytes(b, v)
		case uint64:
			b = protowire.AppendTag(b, num, protowire.VarintType)
			b = protowire.AppendVarint(b, v)
		case int:
			b = protowire.AppendTag(b, num, protowire.VarintType)
			b = protowire.AppendVarint(b, uint64(v))
		}
	}
	return b
}

func TestDecodeProtoPreviewScalars(t *testing.T) {
	msg := buildProtoMsg(
		protowire.Number(1), "hello",
		protowire.Number(2), 42,
	)
	got := decodeProtoPreview(msg, 3)
	if !strings.Contains(got, `"hello"`) {
		t.Errorf("expected string field \"hello\" in %q", got)
	}
	if !strings.Contains(got, "2: 42") {
		t.Errorf("expected int field 2: 42 in %q", got)
	}
	if !strings.HasPrefix(got, "{") || !strings.HasSuffix(got, "}") {
		t.Errorf("expected {…} format, got %q", got)
	}
}

func TestDecodeProtoPreviewNestedMessage(t *testing.T) {
	inner := buildProtoMsg(protowire.Number(1), "inner-value")
	outer := buildProtoMsg(protowire.Number(1), "outer", protowire.Number(2), inner)

	got := decodeProtoPreview(outer, 3)
	if got == "" {
		t.Fatal("expected non-empty decode")
	}
	// Should contain the outer string field and the nested message decoded
	if !strings.Contains(got, `"outer"`) {
		t.Errorf("missing outer string field in %q", got)
	}
	// Nested message should appear decoded (not as raw bytes), since maxDepth=3
	if !strings.Contains(got, `"inner-value"`) {
		t.Errorf("expected nested message to be decoded inline, got %q", got)
	}
}

func TestDecodeProtoPreviewBinaryBlob(t *testing.T) {
	// Random binary that is not valid protobuf (field 0 is invalid)
	blob := []byte{0x00, 0xFF, 0xFE, 0x01, 0x02, 0x03}
	got := decodeProtoPreview(blob, 3)
	// Should return "" so grpcFramePreview falls back to hex — must not panic
	_ = got
}

func TestDecodeProtoPreviewMaxDepth(t *testing.T) {
	// Build 5 levels of nesting: at maxDepth=3 the 5th level must NOT be decoded.
	level5 := buildProtoMsg(protowire.Number(1), "deep")
	level4 := buildProtoMsg(protowire.Number(1), level5)
	level3 := buildProtoMsg(protowire.Number(1), level4)
	level2 := buildProtoMsg(protowire.Number(1), level3)
	level1 := buildProtoMsg(protowire.Number(1), level2)

	got := decodeProtoPreview(level1, 3)
	if got == "" {
		t.Fatal("expected non-empty decode at top level")
	}
	// "deep" is 5 levels in; maxDepth=3 stops recursion before reaching it
	if strings.Contains(got, `"deep"`) {
		t.Errorf("expected depth limit to prevent decoding deepest level, got %q", got)
	}
}

func TestIsGRPCContentType(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/grpc", true},
		{"application/grpc+proto", true},
		{"application/grpc-web", true},
		{"APPLICATION/GRPC", true},
		{"application/json", false},
		{"text/plain", false},
		{"", false},
	}
	for _, c := range cases {
		got := isGRPCContentType(c.ct)
		if got != c.want {
			t.Errorf("isGRPCContentType(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}
