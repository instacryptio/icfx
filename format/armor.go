package format

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
)

const (
	ArmorLockLabel     = "ICFX LOCK"
	ArmorIdentityLabel = "ICFX IDENTITY"
	ArmorICFXLabel     = "ICFX DATA"
	ArmorRevokeLabel   = "ICFX REVOKE"
	ArmorRotateLabel   = "ICFX ROTATE"

	armorLineLen = 76
)

// ArmorEncode wraps data in PEM-style ASCII armor with the given label.
// Base64-encoded, wrapped at 76 chars per line.
//
//	-----BEGIN ICFX LOCK-----
//	<base64>
//	-----END ICFX LOCK-----
func ArmorEncode(data []byte, label string) []byte {
	return ArmorEncodeWithHeaders(data, label, nil)
}

// ArmorEncodeWithHeaders is like ArmorEncode but also writes "Key: Value"
// headers between the BEGIN line and the base64 body, separated from the body
// by a blank line. Header keys are emitted in sorted order for deterministic
// output.
//
//	-----BEGIN ICFX GIT SIGNATURE-----
//	Fingerprint: a1b2c3d4e5f6g7h8
//
//	<base64>
//	-----END ICFX GIT SIGNATURE-----
//
// Passing a nil or empty headers map produces output identical to ArmorEncode.
func ArmorEncodeWithHeaders(data []byte, label string, headers map[string]string) []byte {
	var buf bytes.Buffer
	buf.WriteString("-----BEGIN " + label + "-----\n")

	if len(headers) > 0 {
		keys := make([]string, 0, len(headers))
		for k := range headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			buf.WriteString(k + ": " + headers[k] + "\n")
		}
		buf.WriteByte('\n')
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 0 {
		end := armorLineLen
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[:end])
		buf.WriteByte('\n')
		encoded = encoded[end:]
	}

	buf.WriteString("-----END " + label + "-----\n")
	return buf.Bytes()
}

// ArmorDecode strips armor and returns the decoded payload and label.
// Headers, if present, are silently skipped. Use ArmorDecodeWithHeaders to
// retrieve them.
func ArmorDecode(data []byte) (payload []byte, label string, err error) {
	payload, label, _, err = ArmorDecodeWithHeaders(data)
	return payload, label, err
}

// ArmorDecodeExpect decodes armored data and returns the payload only if the
// armor label is one of want; otherwise it errors. Use it on import paths so a
// mislabeled or wrong-type file (e.g. an ICFX LOCK fed to identity import) is
// rejected up front instead of failing later with a confusing decrypt error.
func ArmorDecodeExpect(data []byte, want ...string) (payload []byte, err error) {
	payload, label, err := ArmorDecode(data)
	if err != nil {
		return nil, err
	}
	for _, w := range want {
		if label == w {
			return payload, nil
		}
	}
	return nil, fmt.Errorf("unexpected armor label %q (want %s)", label, strings.Join(want, " or "))
}

// ArmorDecodeWithHeaders strips armor, returns the decoded payload, label, and
// any "Key: Value" headers between the BEGIN line and the base64 body.
//
// If no headers are present, the returned headers map is non-nil but empty.
func ArmorDecodeWithHeaders(data []byte) (payload []byte, label string, headers map[string]string, err error) {
	s := strings.TrimSpace(strings.ReplaceAll(string(data), "\r\n", "\n"))
	if s == "" {
		return nil, "", nil, fmt.Errorf("empty armored input")
	}

	lines := strings.Split(s, "\n")
	if len(lines) < 2 {
		return nil, "", nil, fmt.Errorf("malformed armor: too few lines")
	}

	header := lines[0]
	if !strings.HasPrefix(header, "-----BEGIN ") || !strings.HasSuffix(header, "-----") {
		return nil, "", nil, fmt.Errorf("malformed armor: invalid header")
	}
	label = header[len("-----BEGIN ") : len(header)-len("-----")]

	expectedFooter := "-----END " + label + "-----"
	footer := lines[len(lines)-1]
	if footer != expectedFooter {
		return nil, "", nil, fmt.Errorf("malformed armor: missing or mismatched footer")
	}

	bodyLines := lines[1 : len(lines)-1]
	headers = make(map[string]string)

	// Headers are present if the first line after BEGIN looks like "Key: Value"
	// and a blank line separates them from the body. We only treat the prefix
	// as headers when we find both: a "Key: Value" line AND a subsequent blank
	// line. Otherwise we treat everything between BEGIN and END as base64.
	if blankIdx := indexBlankLine(bodyLines); blankIdx > 0 && looksLikeHeaders(bodyLines[:blankIdx]) {
		for _, h := range bodyLines[:blankIdx] {
			colon := strings.Index(h, ":")
			if colon <= 0 {
				return nil, "", nil, fmt.Errorf("malformed armor header: %q", h)
			}
			key := strings.TrimSpace(h[:colon])
			value := strings.TrimSpace(h[colon+1:])
			headers[key] = value
		}
		bodyLines = bodyLines[blankIdx+1:]
	}

	b64 := strings.Join(bodyLines, "")
	payload, err = base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, "", nil, fmt.Errorf("malformed armor: invalid base64: %w", err)
	}

	return payload, label, headers, nil
}

// indexBlankLine returns the index of the first blank line in lines, or -1.
func indexBlankLine(lines []string) int {
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			return i
		}
	}
	return -1
}

// looksLikeHeaders returns true if every line is of the form "Key: Value".
// Used to disambiguate headers from base64-only bodies that happen to contain
// a blank line.
func looksLikeHeaders(lines []string) bool {
	if len(lines) == 0 {
		return false
	}
	for _, l := range lines {
		colon := strings.Index(l, ":")
		if colon <= 0 {
			return false
		}
		// First char of key must be a letter (base64 chars include A-Z, a-z, 0-9, +, /, =).
		// "Key: Value" starts with a letter; base64 starts with various chars.
		// We require the colon position to be reasonable for a header.
		if colon > 64 {
			return false
		}
	}
	return true
}

// IsArmored returns true if data starts with a known armor header.
func IsArmored(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	knownLabels := []string{ArmorLockLabel, ArmorIdentityLabel, ArmorICFXLabel, ArmorRevokeLabel, ArmorRotateLabel}
	for _, label := range knownLabels {
		if bytes.HasPrefix(trimmed, []byte("-----BEGIN "+label+"-----")) {
			return true
		}
	}
	return false
}
