package format

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

var (
	MagicBytes            = []byte("ICFX")
	ErrInvalidMagic       = errors.New("invalid ICFX magic bytes")
	ErrInvalidFormat      = errors.New("invalid ICFX format")
	ErrUnsupportedVersion = errors.New("unsupported ICFX version")
)

// A Profile is a container's format profile — a deliberate point in the 2×2
// design space of ICFX containers, chosen along two orthogonal axes:
//
//	                 Buffered (whole-ciphertext sig)   Streaming (digest sig)
//	Public  (header) ProfilePublicBuffered  (0x01)     ProfilePublicStreaming  (0x04)
//	Private (sealed) ProfilePrivateBuffered (0x02)     ProfilePrivateStreaming (0x03)
//
// Visibility — Public keeps metadata (filename, sender fingerprint) in a
// plaintext header: readable without decrypting, but NOT covered by the
// signature (advisory only) — suited to scripting / low-threat automation.
// Private seals metadata inside the encrypted payload, where the signature
// authenticates it and nothing but the ciphertext size is exposed. Default.
//
// Signature model — Buffered signs the whole ciphertext (simple, but must hold
// it in memory to sign/verify; uint32 payload length caps it near 4 GiB).
// Streaming signs a SHA-512 digest of the ciphertext, so encrypt and verify run
// in constant memory regardless of file size (uint64 payload length). Default;
// prefer it for anything that might be large.
//
// The wire byte order is historical (0x01–0x03 predate 0x04); read intent from
// the names, not the numbers.
type Profile byte

const (
	// ProfilePublicBuffered (0x01): public header-only metadata + whole-ciphertext
	// signature. The original ICFX format — lean and transparent; for small data
	// / compatibility. Verification resolves the signer from the header.
	ProfilePublicBuffered Profile = 0x01
	// ProfilePrivateBuffered (0x02): metadata sealed & authenticated inside the
	// payload (EncodePayload) + whole-ciphertext signature. Private, but must
	// buffer the ciphertext to sign/verify.
	ProfilePrivateBuffered Profile = 0x02
	// ProfilePrivateStreaming (0x03): private like ProfilePrivateBuffered, but
	// signs a ciphertext digest so encrypt/decrypt run in constant memory — large
	// files never materialize in RAM. The default profile.
	ProfilePrivateStreaming Profile = 0x03
	// ProfilePublicStreaming (0x04): public header-only metadata like
	// ProfilePublicBuffered, but digest-signed for constant-memory streaming —
	// transparent metadata on large files.
	ProfilePublicStreaming Profile = 0x04
)

// Public reports whether the profile keeps metadata in a plaintext header
// (readable without decrypting, not signature-authenticated) rather than sealed
// inside the encrypted payload.
func (p Profile) Public() bool {
	return p == ProfilePublicBuffered || p == ProfilePublicStreaming
}

// Streaming reports whether the profile signs a ciphertext digest — constant
// memory, uint64 payload length — rather than the whole ciphertext.
func (p Profile) Streaming() bool {
	return p == ProfilePrivateStreaming || p == ProfilePublicStreaming
}

// Metadata holds the .icfx container metadata.
type Metadata struct {
	SenderFingerprint string    `json:"sender_fingerprint"`
	Timestamp         time.Time `json:"timestamp"`
	OriginalFilename  string    `json:"original_filename"`
	IsSigned          bool      `json:"is_signed"`
}

// Container represents a parsed .icfx file. Serialize/Deserialize handle the
// buffered profiles (ProfilePublicBuffered, ProfilePrivateBuffered); the
// streaming profiles use the encrypt/decrypt streaming paths.
type Container struct {
	Profile   Profile
	Metadata  Metadata
	Payload   []byte // age-encrypted ciphertext
	Signature []byte // ML-DSA-65 signature (may be nil if unsigned)
	// Private marks a container without a plaintext header block —
	// Metadata above is zero and the real copy sits inside the encrypted
	// payload (ProfilePrivateBuffered: DecodePayload after decrypting).
	Private bool
}

// Serialize writes a Container to bytes in the .icfx binary format.
// Private containers serialize with an empty header block (metaLen 0).
func (c *Container) Serialize() ([]byte, error) {
	profile := c.Profile
	if profile == 0 {
		profile = ProfilePrivateBuffered
	}
	var metaJSON []byte
	if !c.Private {
		var err error
		metaJSON, err = json.Marshal(c.Metadata)
		if err != nil {
			return nil, fmt.Errorf("marshaling metadata: %w", err)
		}
	}

	metaLen := len(metaJSON)
	if metaLen > 65535 {
		return nil, fmt.Errorf("metadata too large: %d bytes", metaLen)
	}

	payloadLen := len(c.Payload)
	if int64(payloadLen) > math.MaxUint32 {
		return nil, fmt.Errorf("payload too large: %d bytes (buffered max %d; use a streaming profile)", payloadLen, uint64(math.MaxUint32))
	}
	sigLen := len(c.Signature)
	if sigLen > 65535 {
		return nil, fmt.Errorf("signature too large: %d bytes", sigLen)
	}

	totalLen := 4 + 1 + 2 + metaLen + 4 + payloadLen + 2 + sigLen
	buf := make([]byte, totalLen)

	copy(buf[0:4], MagicBytes)
	buf[4] = byte(profile)
	binary.BigEndian.PutUint16(buf[5:7], uint16(metaLen))
	copy(buf[7:7+metaLen], metaJSON)

	offset := 7 + metaLen
	binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(payloadLen))
	copy(buf[offset+4:offset+4+payloadLen], c.Payload)

	offset = offset + 4 + payloadLen
	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(sigLen))
	if sigLen > 0 {
		copy(buf[offset+2:], c.Signature)
	}

	return buf, nil
}

// Deserialize parses .icfx binary data into a Container.
func Deserialize(data []byte) (*Container, error) {
	if len(data) < 7 {
		return nil, ErrInvalidFormat
	}

	if string(data[0:4]) != string(MagicBytes) {
		return nil, ErrInvalidMagic
	}

	profile := Profile(data[4])
	if profile != ProfilePublicBuffered && profile != ProfilePrivateBuffered {
		return nil, ErrUnsupportedVersion
	}

	metaLen := int(binary.BigEndian.Uint16(data[5:7]))
	if len(data) < 7+metaLen+4 {
		return nil, ErrInvalidFormat
	}

	var meta Metadata
	private := metaLen == 0
	if !private {
		if err := json.Unmarshal(data[7:7+metaLen], &meta); err != nil {
			return nil, fmt.Errorf("parsing metadata: %w", err)
		}
	}

	offset := 7 + metaLen
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
// uint16(len(metaJSON)) || metaJSON || filedata. Every v2 payload carries
// this inner copy so the plaintext header is disposable (StripHeader).
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

// DecodePayload splits a decrypted private-profile payload into its inner
// metadata and the original file bytes. Only valid for private profiles
// (ProfilePrivateBuffered / ProfilePrivateStreaming); public-profile payloads
// are the bare file bytes with metadata in the header.
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

// HeaderPrefixLen is the fixed-size container prefix: magic (4) + version
// (1) + header metadata length (2).
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
	switch profile {
	case ProfilePublicBuffered, ProfilePrivateBuffered, ProfilePrivateStreaming, ProfilePublicStreaming:
	default:
		return 0, 0, ErrUnsupportedVersion
	}
	return profile, int(binary.BigEndian.Uint16(head[5:7])), nil
}

// ZeroMetaLen rewrites the header-metadata-length field of a container prefix to
// 0, marking the container private (header block empty). Streaming callers use
// it to strip the plaintext header in place without hardcoding the field offset,
// so the byte layout stays owned by this package. Panics if head is shorter than
// HeaderPrefixLen (a programming error — callers read exactly that many bytes).
func ZeroMetaLen(head []byte) {
	if len(head) < HeaderPrefixLen {
		panic("format.ZeroMetaLen: head shorter than HeaderPrefixLen")
	}
	binary.BigEndian.PutUint16(head[5:7], 0)
}

// StreamHeader locates a streaming container's payload region and trailing
// signature without reading the (potentially huge) payload — the input for a
// constant-memory streaming decrypt. Applies to the streaming profiles
// (ProfilePrivateStreaming, ProfilePublicStreaming).
type StreamHeader struct {
	Profile      Profile
	Private      bool
	HeaderMeta   Metadata // populated only when a plaintext header is present (public)
	PayloadStart int64    // byte offset of the age payload within the container
	PayloadLen   int64    // uint64 on the wire (streaming lifts the buffered 4 GiB cap)
	Signature    []byte   // ML-DSA-65 signature (nil when unsigned)
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
		return nil, ErrUnsupportedVersion
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

// StripHeader re-serializes a BUFFERED container with an EMPTY header block —
// pure byte surgery: payload and signature are untouched, so the signature
// (which covers the payload) stays valid. It returns ErrUnsupportedVersion for
// streaming containers (Deserialize only accepts buffered profiles); the
// streaming upload path strips its header in-place instead (see
// sharing.stripStreamHeader / format.ZeroMetaLen). A stripped PUBLIC buffered
// profile has no inner metadata copy, so its signature becomes unverifiable and
// the original name is lost — acceptable for public files (server-side naming
// covers receive). Private profiles keep their authoritative inner metadata.
func StripHeader(data []byte) ([]byte, error) {
	c, err := Deserialize(data)
	if err != nil {
		return nil, err
	}
	c.Private = true
	c.Metadata = Metadata{}
	return c.Serialize()
}
