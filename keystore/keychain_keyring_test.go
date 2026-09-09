//go:build !darwin

package keystore

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestChunkString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		size int
	}{
		{"empty", "", 4},
		{"smaller than size", "abc", 4},
		{"equal to size", "abcd", 4},
		{"one over", "abcde", 4},
		{"multi chunk", strings.Repeat("x", 4100), 2048},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			chunks := chunkString(c.in, c.size)
			for i, ch := range chunks {
				if len(ch) > c.size {
					t.Fatalf("chunk %d len %d exceeds size %d", i, len(ch), c.size)
				}
			}
			if got := strings.Join(chunks, ""); got != c.in {
				t.Fatalf("rejoined = %q, want %q", got, c.in)
			}
		})
	}
}

func TestParseChunkMarker(t *testing.T) {
	if n, ok := parseChunkMarker(chunkMarker(3)); !ok || n != 3 {
		t.Fatalf("parseChunkMarker(chunkMarker(3)) = (%d, %v), want (3, true)", n, ok)
	}
	// A base64 string is never mistaken for a marker (no '-' or ':' in base64).
	b64 := base64.StdEncoding.EncodeToString([]byte("some key bytes here to encode"))
	if n, ok := parseChunkMarker(b64); ok {
		t.Fatalf("parseChunkMarker(%q) = (%d, true), want ok=false", b64, n)
	}
	if _, ok := parseChunkMarker("icfx-chunks:notanumber"); ok {
		t.Fatal("non-numeric marker parsed as valid")
	}
}

// A >2560-byte signing key round-trips through the chunked path, and Clear removes
// the marker AND every chunk. Uses go-keyring's in-memory mock so it runs headless
// on any platform (the runtime.GOOS gate lives in StoreSigningKey; the test calls
// storeSigningKeyChunked directly to exercise the chunked path regardless of GOOS).
func TestChunkedSigningKeyRoundTrip(t *testing.T) {
	keyring.MockInit()
	k := NewKeychainStore()

	key := make([]byte, 4032) // ML-DSA-65 secret key size → base64 ~5376 > maxKeychainChunk
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)

	if err := k.StoreEncryptionIdentity("id", "age-identity-placeholder"); err != nil {
		t.Fatalf("StoreEncryptionIdentity: %v", err)
	}
	if err := k.storeSigningKeyChunked("id", encoded); err != nil {
		t.Fatalf("storeSigningKeyChunked: %v", err)
	}

	// The main entry is a marker, not the whole key.
	main, err := keyring.Get(keychainService, "id"+signKeySuffix)
	if err != nil {
		t.Fatalf("get main entry: %v", err)
	}
	n, ok := parseChunkMarker(main)
	if !ok || n < 2 {
		t.Fatalf("main entry not a multi-chunk marker: %q", main)
	}

	if got, lerr := k.LoadSigningKey("id"); lerr != nil {
		t.Fatalf("LoadSigningKey: %v", lerr)
	} else if !bytes.Equal(got, key) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(key))
	}

	if !k.HasKeys("id") {
		t.Fatal("HasKeys = false after storing enc + chunked signing key")
	}

	if err := k.Clear("id"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := keyring.Get(keychainService, "id"+signKeySuffix); err == nil {
		t.Fatal("signing key entry still present after Clear")
	}
	for i := 0; i < n; i++ {
		if _, err := keyring.Get(keychainService, fmt.Sprintf("%s.%d", "id"+signKeySuffix, i)); err == nil {
			t.Fatalf("chunk %d still present after Clear", i)
		}
	}
}

// An existing whole-key entry (pre-chunking / Linux) still loads.
func TestWholeSigningKeyBackwardCompat(t *testing.T) {
	keyring.MockInit()
	k := NewKeychainStore()

	key := []byte("a small signing key")
	if err := keyring.Set(keychainService, "id"+signKeySuffix, base64.StdEncoding.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	got, err := k.LoadSigningKey("id")
	if err != nil {
		t.Fatalf("LoadSigningKey (whole): %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("whole-key load mismatch: got %q, want %q", got, key)
	}
}
