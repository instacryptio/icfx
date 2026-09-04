package format

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testMeta() Metadata {
	return Metadata{
		SenderFingerprint: "a1b2c3d4e5f6abcd",
		Timestamp:         time.Now().Truncate(time.Second),
		OriginalFilename:  "secret-report.pdf",
		IsSigned:          true,
	}
}

func TestEncodeDecodePayload(t *testing.T) {
	filedata := []byte("the actual file bytes")
	inner, err := EncodePayload(testMeta(), filedata)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	meta, out, err := DecodePayload(inner)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if meta.OriginalFilename != "secret-report.pdf" || meta.SenderFingerprint != "a1b2c3d4e5f6abcd" || !meta.IsSigned {
		t.Fatalf("inner metadata round-trip: %+v", meta)
	}
	if !bytes.Equal(out, filedata) {
		t.Fatal("file bytes round-trip mismatch")
	}
}

// TestPrivateContainer pins the privacy contract: a private (default)
// container's serialized bytes contain NO metadata plaintext.
func TestPrivateContainer(t *testing.T) {
	c := &Container{
		Profile:   ProfilePrivateBuffered,
		Metadata:  testMeta(), // ignored when Private
		Payload:   []byte("ciphertext"),
		Signature: []byte("sig"),
		Private:   true,
	}
	data, err := c.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if strings.Contains(string(data), "secret-report") || strings.Contains(string(data), "a1b2c3d4") {
		t.Fatal("private container leaked metadata plaintext")
	}
	parsed, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !parsed.Private {
		t.Fatal("expected Private container")
	}
	if parsed.Metadata.SenderFingerprint != "" {
		t.Fatal("private container must deserialize with zero metadata")
	}
	if !bytes.Equal(parsed.Payload, c.Payload) || !bytes.Equal(parsed.Signature, c.Signature) {
		t.Fatal("payload/signature round-trip mismatch")
	}
}

// TestStripHeader: payload + signature bytes survive stripping unchanged
// (the signature covers the payload, so it must stay valid), and the
// stripped bytes carry no metadata plaintext.
func TestStripHeader(t *testing.T) {
	public := &Container{
		Profile:   ProfilePublicBuffered,
		Metadata:  testMeta(),
		Payload:   []byte("payload-bytes-here"),
		Signature: []byte("signature-bytes"),
	}
	data, err := public.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "secret-report.pdf") {
		t.Fatal("public container should carry header metadata (test premise)")
	}

	stripped, err := StripHeader(data)
	if err != nil {
		t.Fatalf("StripHeader: %v", err)
	}
	if strings.Contains(string(stripped), "secret-report") {
		t.Fatal("stripped container still leaks metadata")
	}
	parsed, err := Deserialize(stripped)
	if err != nil {
		t.Fatalf("Deserialize stripped: %v", err)
	}
	if !parsed.Private || parsed.Profile != ProfilePublicBuffered {
		t.Fatalf("stripped container: private=%v profile=%#x", parsed.Private, byte(parsed.Profile))
	}
	if !bytes.Equal(parsed.Payload, public.Payload) || !bytes.Equal(parsed.Signature, public.Signature) {
		t.Fatal("StripHeader must leave payload and signature byte-identical")
	}
}

// TestV1Compat: hand-built v1 bytes (the pre-v2 layout with plaintext header
// metadata and a bare payload) still deserialize with header metadata.
func TestV1Compat(t *testing.T) {
	metaJSON, _ := json.Marshal(testMeta())
	payload := []byte("v1-age-ciphertext")
	sig := []byte("v1-sig")

	buf := make([]byte, 0, 64)
	buf = append(buf, MagicBytes...)
	buf = append(buf, byte(ProfilePublicBuffered))
	var l2 [2]byte
	binary.BigEndian.PutUint16(l2[:], uint16(len(metaJSON)))
	buf = append(buf, l2[:]...)
	buf = append(buf, metaJSON...)
	var l4 [4]byte
	binary.BigEndian.PutUint32(l4[:], uint32(len(payload)))
	buf = append(buf, l4[:]...)
	buf = append(buf, payload...)
	binary.BigEndian.PutUint16(l2[:], uint16(len(sig)))
	buf = append(buf, l2[:]...)
	buf = append(buf, sig...)

	parsed, err := Deserialize(buf)
	if err != nil {
		t.Fatalf("Deserialize v1: %v", err)
	}
	if parsed.Profile != ProfilePublicBuffered || parsed.Private {
		t.Fatalf("v1 parse: profile=%#x private=%v", byte(parsed.Profile), parsed.Private)
	}
	if parsed.Metadata.OriginalFilename != "secret-report.pdf" {
		t.Fatalf("v1 header metadata lost: %+v", parsed.Metadata)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatal("v1 payload mismatch")
	}

	// Stripping a v1 keeps its profile byte and drops the header.
	stripped, err := StripHeader(buf)
	if err != nil {
		t.Fatalf("StripHeader v1: %v", err)
	}
	sp, err := Deserialize(stripped)
	if err != nil {
		t.Fatal(err)
	}
	if sp.Profile != ProfilePublicBuffered || !sp.Private || !bytes.Equal(sp.Payload, payload) {
		t.Fatalf("stripped v1: profile=%#x private=%v", byte(sp.Profile), sp.Private)
	}
}

func TestParseHeaderPrefix(t *testing.T) {
	c := &Container{Profile: ProfilePublicBuffered, Metadata: testMeta(), Payload: []byte("p")}
	data, err := c.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	profile, metaLen, err := ParseHeaderPrefix(data[:HeaderPrefixLen])
	if err != nil {
		t.Fatalf("ParseHeaderPrefix: %v", err)
	}
	if profile != ProfilePublicBuffered || metaLen == 0 {
		t.Fatalf("prefix parse: profile=%#x metaLen=%d", byte(profile), metaLen)
	}
	if _, _, err := ParseHeaderPrefix([]byte("BOGUS12")); err == nil {
		t.Fatal("bogus magic must fail")
	}
}
