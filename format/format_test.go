package format

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
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

// legacyBuffered hand-builds a legacy buffered container (uint32 payload
// length). meta == nil leaves the header block empty.
func legacyBuffered(t *testing.T, profile Profile, meta *Metadata, payload, sig []byte) []byte {
	t.Helper()
	var metaJSON []byte
	if meta != nil {
		var err error
		if metaJSON, err = json.Marshal(meta); err != nil {
			t.Fatal(err)
		}
	}
	buf := append([]byte{}, MagicBytes...)
	buf = append(buf, byte(profile))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(metaJSON)))
	buf = append(buf, metaJSON...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(payload)))
	buf = append(buf, payload...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(sig)))
	return append(buf, sig...)
}

// streaming hand-builds a streaming-layout container (uint64 payload length).
func streaming(t *testing.T, profile Profile, meta *Metadata, payload, sig []byte) []byte {
	t.Helper()
	var metaJSON []byte
	if meta != nil {
		var err error
		if metaJSON, err = json.Marshal(meta); err != nil {
			t.Fatal(err)
		}
	}
	buf := append([]byte{}, MagicBytes...)
	buf = append(buf, byte(profile))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(metaJSON)))
	buf = append(buf, metaJSON...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(len(payload)))
	buf = append(buf, payload...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(sig)))
	return append(buf, sig...)
}

func TestProfilePredicates(t *testing.T) {
	cases := []struct {
		p                                        Profile
		valid, legacy, public, streaming, sealed bool
	}{
		{LegacyProfilePublicBuffered, true, true, true, false, false},
		{LegacyProfilePrivateBuffered, true, true, false, false, true},
		{LegacyProfilePrivateStreaming, true, true, false, true, true},
		{LegacyProfilePublicStreaming, true, true, true, true, false},
		{ProfilePrivate, true, false, false, true, true},
		{ProfilePublic, true, false, true, true, true},
		{Profile(0x00), false, false, false, false, false},
		{Profile(0x07), false, false, false, false, false},
	}
	for _, c := range cases {
		got := [5]bool{c.p.Valid(), c.p.Legacy(), c.p.Public(), c.p.Streaming(), c.p.SealsMetadata()}
		want := [5]bool{c.valid, c.legacy, c.public, c.streaming, c.sealed}
		if got != want {
			t.Errorf("profile %#x: valid/legacy/public/streaming/sealed = %v, want %v", byte(c.p), got, want)
		}
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
	if !meta.Equal(testMeta()) {
		t.Fatalf("inner metadata round-trip: %+v", meta)
	}
	if !bytes.Equal(out, filedata) {
		t.Fatal("file bytes round-trip mismatch")
	}
	if _, _, err := DecodePayload([]byte{0xFF, 0xFF, 0x00}); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("truncated inner metadata: want ErrInvalidFormat, got %v", err)
	}
}

func TestMetadataEqual(t *testing.T) {
	a := testMeta()
	if !a.Equal(a) {
		t.Fatal("metadata must equal itself")
	}
	b := a
	b.OriginalFilename = "other.pdf"
	if a.Equal(b) {
		t.Fatal("different filename must not be equal")
	}
	c := a
	c.SenderFingerprint = "0000000000000000"
	if a.Equal(c) {
		t.Fatal("different fingerprint must not be equal")
	}
}

func TestDeserializeLegacyBuffered(t *testing.T) {
	meta := testMeta()
	payload, sig := []byte("age-ciphertext"), []byte("signature-bytes")

	headered, err := Deserialize(legacyBuffered(t, LegacyProfilePublicBuffered, &meta, payload, sig))
	if err != nil {
		t.Fatalf("Deserialize headered: %v", err)
	}
	if headered.Profile != LegacyProfilePublicBuffered || headered.Private || !headered.Metadata.Equal(meta) {
		t.Fatalf("headered parse: %+v", headered)
	}
	if !bytes.Equal(headered.Payload, payload) || !bytes.Equal(headered.Signature, sig) {
		t.Fatal("payload/signature mismatch")
	}

	private, err := Deserialize(legacyBuffered(t, LegacyProfilePrivateBuffered, nil, payload, nil))
	if err != nil {
		t.Fatalf("Deserialize private: %v", err)
	}
	if !private.Private || private.Metadata.SenderFingerprint != "" || len(private.Signature) != 0 {
		t.Fatalf("private parse: %+v", private)
	}
	if strings.Contains(string(legacyBuffered(t, LegacyProfilePrivateBuffered, nil, payload, nil)), "secret-report") {
		t.Fatal("private container leaked metadata plaintext")
	}
}

func TestDeserializeRejects(t *testing.T) {
	meta := testMeta()
	for _, p := range []Profile{LegacyProfilePrivateStreaming, LegacyProfilePublicStreaming, ProfilePrivate, ProfilePublic} {
		if _, err := Deserialize(streaming(t, p, &meta, []byte("p"), nil)); !errors.Is(err, ErrUnsupportedProfile) {
			t.Errorf("profile %#x: want ErrUnsupportedProfile, got %v", byte(p), err)
		}
	}
	if _, err := Deserialize([]byte("NOPE\x01\x00\x00")); !errors.Is(err, ErrInvalidMagic) {
		t.Errorf("bad magic: want ErrInvalidMagic, got %v", err)
	}
	if _, err := Deserialize([]byte("ICFX")); !errors.Is(err, ErrInvalidFormat) {
		t.Errorf("too short: want ErrInvalidFormat, got %v", err)
	}
	// A declared payload length past the end must be rejected, not panic.
	whole := legacyBuffered(t, LegacyProfilePrivateBuffered, nil, []byte("hello"), nil)
	if _, err := Deserialize(whole[:len(whole)-4]); err == nil {
		t.Fatal("Deserialize accepted a truncated container; want error")
	}
}

func TestParseHeaderPrefix(t *testing.T) {
	meta := testMeta()
	data := streaming(t, ProfilePublic, &meta, []byte("p"), nil)
	profile, metaLen, err := ParseHeaderPrefix(data[:HeaderPrefixLen])
	if err != nil {
		t.Fatalf("ParseHeaderPrefix: %v", err)
	}
	if profile != ProfilePublic || metaLen == 0 {
		t.Fatalf("prefix parse: profile=%#x metaLen=%d", byte(profile), metaLen)
	}
	if _, _, err := ParseHeaderPrefix([]byte("BOGUS12")); !errors.Is(err, ErrInvalidMagic) {
		t.Fatal("bogus magic must fail")
	}
	if _, _, err := ParseHeaderPrefix([]byte("ICFX\x09\x00\x00")); !errors.Is(err, ErrUnsupportedProfile) {
		t.Fatal("unknown profile must fail")
	}

	head := append([]byte{}, data[:HeaderPrefixLen]...)
	ZeroMetaLen(head)
	if _, metaLen, _ := ParseHeaderPrefix(head); metaLen != 0 {
		t.Fatal("ZeroMetaLen must clear the header length")
	}
}

func TestParseStreamHeader(t *testing.T) {
	meta := testMeta()
	payload, sig := []byte("age-ciphertext-bytes"), []byte("sig")

	pub, err := ParseStreamHeader(bytes.NewReader(streaming(t, ProfilePublic, &meta, payload, sig)))
	if err != nil {
		t.Fatalf("ParseStreamHeader public: %v", err)
	}
	if pub.Profile != ProfilePublic || pub.Private || !pub.HeaderMeta.Equal(meta) {
		t.Fatalf("public header: %+v", pub)
	}
	if pub.PayloadLen != int64(len(payload)) || !bytes.Equal(pub.Signature, sig) {
		t.Fatalf("public offsets: %+v", pub)
	}
	data := streaming(t, ProfilePublic, &meta, payload, sig)
	if !bytes.Equal(data[pub.PayloadStart:pub.PayloadStart+pub.PayloadLen], payload) {
		t.Fatal("PayloadStart does not locate the payload")
	}

	priv, err := ParseStreamHeader(bytes.NewReader(streaming(t, ProfilePrivate, nil, payload, nil)))
	if err != nil {
		t.Fatalf("ParseStreamHeader private: %v", err)
	}
	if !priv.Private || priv.Signature != nil || priv.HeaderMeta.SenderFingerprint != "" {
		t.Fatalf("private header: %+v", priv)
	}

	if _, err := ParseStreamHeader(bytes.NewReader(legacyBuffered(t, LegacyProfilePrivateBuffered, nil, payload, nil))); !errors.Is(err, ErrUnsupportedProfile) {
		t.Fatalf("buffered layout through ParseStreamHeader: want ErrUnsupportedProfile, got %v", err)
	}
}

func TestParseStreamHeaderRejectsHostileLengths(t *testing.T) {
	meta := testMeta()
	data := streaming(t, ProfilePublic, &meta, []byte("short payload"), nil)
	sh, err := ParseStreamHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	lenOff := sh.PayloadStart - 8
	for _, claimed := range []uint64{math.MaxUint64, math.MaxInt64, math.MaxInt64 - 1, 1 << 40} {
		hostile := append([]byte{}, data...)
		binary.BigEndian.PutUint64(hostile[lenOff:lenOff+8], claimed)
		if _, err := ParseStreamHeader(bytes.NewReader(hostile)); err == nil {
			t.Fatalf("PayloadLen %d must be rejected", claimed)
		}
	}
	if !bytes.Equal(sh.HeaderRaw, data[HeaderPrefixLen:HeaderPrefixLen+len(sh.HeaderRaw)]) {
		t.Fatal("HeaderRaw must be the header bytes verbatim")
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want Format
	}{
		{"ICFX", []byte("ICFX\x05rest-of-data"), FormatICFX},
		{"age", []byte("age-encryption.org/v1\n..."), FormatAge},
		{"unknown", []byte("random data"), FormatUnknown},
		{"empty", []byte{}, FormatUnknown},
		{"short", []byte("IC"), FormatUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Detect(tt.data); got != tt.want {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatString(t *testing.T) {
	tests := []struct {
		f    Format
		want string
	}{
		{FormatICFX, "icfx"},
		{FormatAge, "age"},
		{FormatUnknown, "unknown"},
	}
	for _, tt := range tests {
		if got := tt.f.String(); got != tt.want {
			t.Errorf("Format(%d).String() = %q, want %q", tt.f, got, tt.want)
		}
	}
}
