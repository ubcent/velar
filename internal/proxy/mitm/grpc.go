package mitm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

// grpcFramePreview extracts the first gRPC frame from body and returns a human-readable preview.
// gRPC wire format: [1 byte compressed flag][4 bytes message length big-endian][N bytes message].
// Returns "" if the body is too short to contain a valid frame header.
func grpcFramePreview(body []byte) string {
	if len(body) < 5 {
		return ""
	}
	compressed := body[0]
	msgLen := binary.BigEndian.Uint32(body[1:5])
	if compressed == 1 {
		return fmt.Sprintf("[compressed, %d bytes]", msgLen)
	}
	msg := body[5:]
	if uint32(len(msg)) > msgLen {
		msg = msg[:msgLen]
	}
	limit := 512
	if len(msg) < limit {
		limit = len(msg)
	}
	msg = msg[:limit]

	if decoded := decodeProtoPreview(msg, 3); decoded != "" {
		return decoded
	}
	return hex.EncodeToString(msg)
}

// decodeProtoPreview decodes a raw protobuf message into a human-readable string
// without requiring a .proto schema. maxDepth controls recursion for nested messages
// and is capped at 3 to avoid unbounded recursion.
//
// Output format: {1: "hello", 2: 42, 3: <bytes 6>}
func decodeProtoPreview(msg []byte, maxDepth int) string {
	if maxDepth > 3 {
		maxDepth = 3
	}

	var parts []string
	b := msg

	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return "" // malformed — signal caller to fall back
		}
		b = b[n:]

		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return ""
			}
			b = b[n:]
			parts = append(parts, fmt.Sprintf("%d: %d", num, v))

		case protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				return ""
			}
			b = b[n:]
			parts = append(parts, fmt.Sprintf("%d: %d", num, v))

		case protowire.Fixed32Type:
			v, n := protowire.ConsumeFixed32(b)
			if n < 0 {
				return ""
			}
			b = b[n:]
			parts = append(parts, fmt.Sprintf("%d: %d", num, v))

		case protowire.BytesType:
			raw, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return ""
			}
			b = b[n:]
			parts = append(parts, fmt.Sprintf("%d: %s", num, decodeLenDelim(raw, maxDepth)))

		case protowire.StartGroupType:
			raw, n := protowire.ConsumeGroup(num, b)
			if n < 0 {
				return ""
			}
			b = b[n:]
			parts = append(parts, fmt.Sprintf("%d: %s", num, decodeLenDelim(raw, maxDepth)))

		default:
			return "" // unknown wire type — signal caller to fall back
		}
	}

	if len(parts) == 0 {
		return ""
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// decodeLenDelim tries to render a length-delimited value:
//  1. If valid printable UTF-8 string → quoted string
//  2. If maxDepth > 0 and looks like a nested proto → recursive decode
//  3. Otherwise → "<bytes N>"
func decodeLenDelim(raw []byte, maxDepth int) string {
	if isPrintableUTF8(raw) {
		return fmt.Sprintf("%q", string(raw))
	}
	if maxDepth > 0 {
		if nested := decodeProtoPreview(raw, maxDepth-1); nested != "" {
			return nested
		}
	}
	return fmt.Sprintf("<bytes %d>", len(raw))
}

func isPrintableUTF8(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
		if r == utf8.RuneError {
			return false
		}
	}
	return true
}

func isGRPCContentType(ct string) bool {
	return strings.HasPrefix(strings.ToLower(ct), "application/grpc")
}
