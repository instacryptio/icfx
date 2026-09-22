package format

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

var (
	MagicBytes            = []byte("ICFX")
	ErrInvalidMagic       = errors.New("invalid ICFX magic bytes")
	ErrInvalidFormat      = errors.New("invalid ICFX format")
	ErrUnsupportedProfile = errors.New("unsupported ICFX profile")
)

// A Profile is the byte after the magic that selects a container's layout.
//
// Two profiles are written. Both stream (uint64 payload length, so encrypt and
// decrypt run in constant memory) and both seal the metadata — sender
// fingerprint, filename, timestamp — inside the encrypted payload, where the
// signature covers it:
//
//	ProfilePrivate (0x05)  nothing but the ciphertext size is visible on the
//	                       wire. The default.
//	ProfilePublic  (0x06)  additionally carries an ADVISORY plaintext copy of
//	                       the metadata in the header so tooling can read the
//	                       filename without decrypting. The copy is never used
//	                       to resolve the signer, and one that disagrees with
//	                       the sealed metadata fails verification.
//
// The Legacy* profiles are the layouts written before the signature covered
// the plaintext. They still decrypt so existing files stay readable, but their
// signatures are no longer honoured: a signed legacy container reports
// VerifyFailed and the caller decides whether to keep the plaintext.
type Profile byte

const (
	// LegacyProfilePublicBuffered (0x01): plaintext header metadata, bare file
	// bytes as payload, uint32 payload length. Decrypt only.
	LegacyProfilePublicBuffered Profile = 0x01
	// LegacyProfilePrivateBuffered (0x02): metadata sealed inside the payload
	// (EncodePayload framing), uint32 payload length. Decrypt only.
	LegacyProfilePrivateBuffered Profile = 0x02
	// LegacyProfilePrivateStreaming (0x03): sealed metadata, uint64 payload
	// length. Decrypt only.
	LegacyProfilePrivateStreaming Profile = 0x03
	// LegacyProfilePublicStreaming (0x04): plaintext header metadata, bare file
	// bytes as payload, uint64 payload length. Decrypt only.
	LegacyProfilePublicStreaming Profile = 0x04
	// ProfilePrivate (0x05): sealed metadata, empty header. The default.
	ProfilePrivate Profile = 0x05
	// ProfilePublic (0x06): sealed metadata plus an advisory header copy.
	ProfilePublic Profile = 0x06
)

// Valid reports whether p is a profile this build can parse.
func (p Profile) Valid() bool {
	switch p {
	case LegacyProfilePublicBuffered, LegacyProfilePrivateBuffered,
		LegacyProfilePrivateStreaming, LegacyProfilePublicStreaming,
		ProfilePrivate, ProfilePublic:
		return true
	}
	return false
}

// Legacy reports whether p is a decrypt-only layout whose signature (if any)
// is no longer honoured.
func (p Profile) Legacy() bool {
	switch p {
	case LegacyProfilePublicBuffered, LegacyProfilePrivateBuffered,
		LegacyProfilePrivateStreaming, LegacyProfilePublicStreaming:
		return true
	}
	return false
}

// Public reports whether the profile carries metadata in a plaintext header.
// For ProfilePublic that copy is advisory; the sealed copy is authoritative.
func (p Profile) Public() bool {
	switch p {
	case LegacyProfilePublicBuffered, LegacyProfilePublicStreaming, ProfilePublic:
		return true
	}
	return false
}

// Streaming reports whether the profile uses a uint64 payload length and the
// streaming container layout (rather than the legacy uint32 buffered one).
func (p Profile) Streaming() bool {
	switch p {
	case LegacyProfilePrivateStreaming, LegacyProfilePublicStreaming, ProfilePrivate, ProfilePublic:
		return true
	}
	return false
}

// SealsMetadata reports whether the encrypted payload begins with the inner
// metadata framing (uint16 metaLen || metaJSON) ahead of the file bytes.
func (p Profile) SealsMetadata() bool {
	switch p {
	case LegacyProfilePrivateBuffered, LegacyProfilePrivateStreaming, ProfilePrivate, ProfilePublic:
		return true
	}
	return false
}

// Metadata holds the .icfx container metadata.
type Metadata struct {
	SenderFingerprint string    `json:"sender_fingerprint"`
	Timestamp         time.Time `json:"timestamp"`
	OriginalFilename  string    `json:"original_filename"`
	IsSigned          bool      `json:"is_signed"`
}

// Equal reports whether two metadata records describe the same container.
// Used to check a ProfilePublic advisory header against the sealed copy.
func (m Metadata) Equal(o Metadata) bool {
	return m.SenderFingerprint == o.SenderFingerprint &&
		m.OriginalFilename == o.OriginalFilename &&
		m.IsSigned == o.IsSigned &&
		m.Timestamp.Equal(o.Timestamp)
}

// Container is a parsed legacy buffered container (LegacyProfilePublicBuffered
// / LegacyProfilePrivateBuffered). Streaming profiles are read with
// ParseStreamHeader instead.
type Container struct {
	Profile   Profile
	Metadata  Metadata
	Payload   []byte // age-encrypted ciphertext
	Signature []byte // ML-DSA-65 signature (nil if unsigned)
	// Private marks a container without a plaintext header block — Metadata
	// above is zero and any real copy sits inside the encrypted payload
	// (DecodePayload after decrypting, for profiles that seal it).
	Private bool
}

// Deserialize parses a legacy buffered container:
// magic|profile|metaLen(u16)|[meta]|payloadLen(u32)|payload|sigLen(u16)|[sig].
func Deserialize(data []byte) (*Container, error) {
	if len(data) < HeaderPrefixLen {
		return nil, ErrInvalidFormat
	}
	if string(data[0:4]) != string(MagicBytes) {
		return nil, ErrInvalidMagic
	}
	profile := Profile(data[4])
	if !profile.Legacy() || profile.Streaming() {
		return nil, ErrUnsupportedProfile
	}

	metaLen := int(binary.BigEndian.Uint16(data[5:7]))
	if len(data) < HeaderPrefixLen+metaLen+4 {
		return nil, ErrInvalidFormat
	}

	var meta Metadata
	private := metaLen == 0
	if !private {
		if err := json.Unmarshal(data[HeaderPrefixLen:HeaderPrefixLen+metaLen], &meta); err != nil {
			return nil, fmt.Errorf("parsing metadata: %w", err)
		}
	}

	offset := HeaderPrefixLen + metaLen
	// Compare in int64 so a payloadLen near math.MaxUint32 can't overflow int
	// (negative on 32-bit builds) and bypass the bounds check before make.
	payloadLen := int64(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if int64(len(data)-offset) < payloadLen+2 {
		return nil, ErrInvalidFormat
	}

	plen := int(payloadLen)
	payload := make([]byte, plen)
	copy(payload, data[offset:offset+plen])
	offset += plen

	sigLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	var signature []byte
	if sigLen > 0 {
		if len(data) < offset+sigLen {
			return nil, ErrInvalidFormat
		}
		signature = make([]byte, sigLen)
		copy(signature, data[offset:offset+sigLen])
	}

	return &Container{
		Profile:   profile,
		Metadata:  meta,
		Payload:   payload,
		Signature: signature,
		Private:   private,
	}, nil
}

// EncodePayload frames metadata ahead of the file bytes for encryption:
// uint16(len(metaJSON)) || metaJSON || filedata. This sealed copy is the
// authoritative metadata; any plaintext header is disposable.
func EncodePayload(meta Metadata, filedata []byte) ([]byte, error) {
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshaling inner metadata: %w", err)
	}
	if len(metaJSON) > 65535 {
		return nil, fmt.Errorf("inner metadata too large: %d bytes", len(metaJSON))
	}
	out := make([]byte, 2+len(metaJSON)+len(filedata))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(metaJSON)))
	copy(out[2:], metaJSON)
	copy(out[2+len(metaJSON):], filedata)
	return out, nil
}

// DecodePayload splits a decrypted payload that seals its metadata
// (Profile.SealsMetadata) into the inner metadata and the original file bytes.
func DecodePayload(plaintext []byte) (Metadata, []byte, error) {
	if len(plaintext) < 2 {
		return Metadata{}, nil, ErrInvalidFormat
	}
	metaLen := int(binary.BigEndian.Uint16(plaintext[0:2]))
	if len(plaintext) < 2+metaLen {
		return Metadata{}, nil, ErrInvalidFormat
	}
	var meta Metadata
	if err := json.Unmarshal(plaintext[2:2+metaLen], &meta); err != nil {
		return Metadata{}, nil, fmt.Errorf("parsing inner metadata: %w", err)
	}
	return meta, plaintext[2+metaLen:], nil
}

// HeaderPrefixLen is the fixed-size container prefix: magic (4) + profile (1)
// + header metadata length (2).
const HeaderPrefixLen = 7

// ParseHeaderPrefix validates the fixed prefix of a serialized container and
// returns its profile and header-metadata length. Lets streaming callers strip
// the header without buffering the (potentially huge) payload.
func ParseHeaderPrefix(head []byte) (profile Profile, metaLen int, err error) {
	if len(head) < HeaderPrefixLen {
		return 0, 0, ErrInvalidFormat
	}
	if string(head[0:4]) != string(MagicBytes) {
		return 0, 0, ErrInvalidMagic
	}
	profile = Profile(head[4])
	if !profile.Valid() {
		return 0, 0, ErrUnsupportedProfile
	}
	return profile, int(binary.BigEndian.Uint16(head[5:7])), nil
}

// ZeroMetaLen rewrites the header-metadata-length field of a container prefix
// to 0, dropping the plaintext header block. The sharing upload path uses it to
// strip the header in place without hardcoding the field offset, so the byte
// layout stays owned by this package. Panics if head is shorter than
// HeaderPrefixLen (a programming error — callers read exactly that many bytes).
func ZeroMetaLen(head []byte) {
	if len(head) < HeaderPrefixLen {
		panic("format.ZeroMetaLen: head shorter than HeaderPrefixLen")
	}
	binary.BigEndian.PutUint16(head[5:7], 0)
}

// StreamHeader locates a streaming container's payload region and trailing
// signature without reading the (potentially huge) payload — the input for a
// constant-memory decrypt.
type StreamHeader struct {
	Profile      Profile
	Private      bool     // no plaintext header block (metaLen 0)
	HeaderMeta   Metadata // populated only when a plaintext header is present
	PayloadStart int64    // byte offset of the age payload within the container
	PayloadLen   int64    // uint64 on the wire
	Signature    []byte   // ML-DSA-65 signature (nil when absent)
}

// ParseStreamHeader reads a streaming container's framing from r (seeking as
// needed) and returns its payload offsets + signature WITHOUT loading the
// payload. The signature is small, so it is read into memory. r's final offset
// is unspecified; seek to PayloadStart before reading the payload.
func ParseStreamHeader(r io.ReadSeeker) (*StreamHeader, error) {
	head := make([]byte, HeaderPrefixLen)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("reading header prefix: %w", err)
	}
	profile, metaLen, err := ParseHeaderPrefix(head)
	if err != nil {
		return nil, err
	}
	if !profile.Streaming() {
		return nil, ErrUnsupportedProfile
	}
	sh := &StreamHeader{Profile: profile, Private: metaLen == 0}
	if metaLen > 0 {
		mbuf := make([]byte, metaLen)
		if _, err := io.ReadFull(r, mbuf); err != nil {
			return nil, fmt.Errorf("reading header metadata: %w", err)
		}
		if err := json.Unmarshal(mbuf, &sh.HeaderMeta); err != nil {
			return nil, fmt.Errorf("parsing header metadata: %w", err)
		}
	}
	var plbuf [8]byte
	if _, err := io.ReadFull(r, plbuf[:]); err != nil {
		return nil, fmt.Errorf("reading payload length: %w", err)
	}
	sh.PayloadLen = int64(binary.BigEndian.Uint64(plbuf[:]))
	if sh.PayloadLen < 0 {
		return nil, ErrInvalidFormat
	}
	sh.PayloadStart = int64(HeaderPrefixLen + metaLen + 8)
	// The signature length + bytes follow the payload.
	if _, err := r.Seek(sh.PayloadStart+sh.PayloadLen, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seeking to signature: %w", err)
	}
	var slbuf [2]byte
	if _, err := io.ReadFull(r, slbuf[:]); err != nil {
		return nil, fmt.Errorf("reading signature length: %w", err)
	}
	if sigLen := int(binary.BigEndian.Uint16(slbuf[:])); sigLen > 0 {
		sig := make([]byte, sigLen)
		if _, err := io.ReadFull(r, sig); err != nil {
			return nil, fmt.Errorf("reading signature: %w", err)
		}
		sh.Signature = sig
	}
	return sh, nil
}
