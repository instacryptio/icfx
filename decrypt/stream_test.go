package decrypt

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/encrypt"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/identity"
)

// encryptStreaming produces a streaming container via the encrypt path. private
// selects ProfilePrivateStreaming (metadata sealed inside), else
// ProfilePublicStreaming (metadata in a readable plaintext header).
func encryptStreaming(t *testing.T, sender, recipient *party, filedata []byte, private, signed bool) []byte {
	t.Helper()
	profile := format.ProfilePrivateStreaming
	if !private {
		profile = format.ProfilePublicStreaming
	}
	meta := format.Metadata{
		SenderFingerprint: sender.kp.Fingerprint,
		Timestamp:         time.Now().UTC(),
		OriginalFilename:  "test.bin",
		IsSigned:          signed,
	}
	var signer *identity.Unlocked
	if signed {
		signer = sender.u
	}
	var buf bytes.Buffer
	if err := encrypt.EncryptStream(&buf, bytes.NewReader(filedata), []string{recipient.kp.EncryptionRecipient}, signer, meta, profile); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	out := buf.Bytes()
	if len(out) < 5 || out[4] != byte(profile) {
		t.Fatalf("expected profile byte %#x, got %x", byte(profile), out[:5])
	}
	if !private && !bytes.Contains(out, []byte("test.bin")) {
		t.Fatal("public container should carry the plaintext header filename")
	}
	if private && bytes.Contains(out, []byte("test.bin")) {
		t.Fatal("private container leaked the filename")
	}
	return out
}

func decryptV3(t *testing.T, container []byte, u *identity.Unlocked, cl []contacts.Contact) ([]byte, VerifyResult) {
	t.Helper()
	var out bytes.Buffer
	res, err := DecryptAndVerifyStream(bytes.NewReader(container), &out, u, cl)
	if err != nil {
		t.Fatalf("DecryptAndVerifyStream: %v", err)
	}
	return out.Bytes(), res
}

func TestV3PrivateSignedContactMatch(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("private v3 payload")
	data := encryptStreaming(t, sender, recipient, file, true, true)

	plain, res := decryptV3(t, data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if !bytes.Equal(plain, file) {
		t.Fatalf("plaintext mismatch: %q", plain)
	}
	if res.Status != VerifyOK || res.SignerAlias != "alice" || res.UsedRevokedKey {
		t.Fatalf("want OK via contact alice, got %+v", res)
	}
}

func TestV3PublicSignedContactMatch(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("public-meta v3")
	data := encryptStreaming(t, sender, recipient, file, false, true)

	plain, res := decryptV3(t, data, recipient.u, []contacts.Contact{contactFor("bob", sender)})
	if !bytes.Equal(plain, file) {
		t.Fatal("plaintext mismatch")
	}
	if res.Status != VerifyOK || res.SignerAlias != "bob" {
		t.Fatalf("want OK via contact bob, got %+v", res)
	}
}

func TestV3SelfSigned(t *testing.T) {
	self := newParty(t, "me")
	file := []byte("dear v3 diary")
	data := encryptStreaming(t, self, self, file, true, true)

	plain, res := decryptV3(t, data, self.u, nil)
	if !bytes.Equal(plain, file) {
		t.Fatal("plaintext mismatch")
	}
	if res.Status != VerifyOK || res.SignerIdentity != "me" {
		t.Fatalf("want OK via self, got %+v", res)
	}
}

func TestV3Unsigned(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("no signature here")
	data := encryptStreaming(t, sender, recipient, file, true, false)

	plain, res := decryptV3(t, data, recipient.u, nil)
	if !bytes.Equal(plain, file) {
		t.Fatal("plaintext mismatch")
	}
	if res.Status != VerifyUnsigned {
		t.Fatalf("want VerifyUnsigned, got %+v", res)
	}
}

func TestV3UnknownSender(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := encryptStreaming(t, sender, recipient, []byte("x"), true, true)

	_, res := decryptV3(t, data, recipient.u, nil) // no contacts, recipient != sender
	if res.Status != VerifyUnverifiable || res.SignerFP != sender.kp.Fingerprint {
		t.Fatalf("want Unverifiable with signer fp, got %+v", res)
	}
}

func TestV3TamperedCiphertext(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := encryptStreaming(t, sender, recipient, []byte("tamper me"), true, true)

	// Flip a byte in the middle (the payload region).
	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[len(tampered)/2] ^= 0xFF

	var out bytes.Buffer
	res, err := DecryptAndVerifyStream(bytes.NewReader(tampered), &out, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	// age may reject the tampered ciphertext (decrypt error) OR the signature
	// fails — either way it must NOT report VerifyOK.
	if err == nil && res.Status == VerifyOK {
		t.Fatalf("tampered ciphertext must not verify OK, got %+v", res)
	}
}

func TestV3TamperedSignature(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := encryptStreaming(t, sender, recipient, []byte("payload"), true, true)

	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[len(tampered)-1] ^= 0xFF // last byte is inside the signature

	_, res := decryptV3(t, tampered, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if res.Status != VerifyUnverifiable {
		t.Fatalf("want Unverifiable for tampered sig, got %+v", res)
	}
}

func TestV3WrongRecipientCannotDecrypt(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	stranger := newParty(t, "stranger")
	data := encryptStreaming(t, sender, recipient, []byte("secret"), true, true)

	var out bytes.Buffer
	if _, err := DecryptAndVerifyStream(bytes.NewReader(data), &out, stranger.u, nil); err == nil {
		t.Fatal("want decrypt error for wrong recipient")
	}
}

// TestV3LargerPayload round-trips a multi-MB payload to exercise the streaming
// path across several age chunks.
func TestV3LargerPayload(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := make([]byte, 5<<20) // 5 MiB
	if _, err := rand.Read(file); err != nil {
		t.Fatal(err)
	}
	data := encryptStreaming(t, sender, recipient, file, true, true)

	plain, res := decryptV3(t, data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if !bytes.Equal(plain, file) {
		t.Fatal("large payload mismatch")
	}
	if res.Status != VerifyOK {
		t.Fatalf("want OK, got %+v", res)
	}
}

// TestV3StreamAcceptsV2 confirms the streaming entrypoint transparently handles a
// v2 container via the buffered fallback (cross-version).
func TestV3StreamAcceptsV2(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("legacy v2 through the stream API")
	v2 := buildContainer(t, file, buildOpts{private: true, signed: true, sender: sender, recipient: recipient})

	plain, res := decryptV3(t, v2, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if !bytes.Equal(plain, file) {
		t.Fatal("v2 via stream API: plaintext mismatch")
	}
	if res.Status != VerifyOK || res.SignerAlias != "alice" {
		t.Fatalf("v2 via stream API: want OK, got %+v", res)
	}
}

// TestV4HeaderReadableWithoutDecrypt is the point of the public streaming
// profile: a script can read the metadata (filename, sender fingerprint) from
// the plaintext header without ever decrypting the payload.
func TestV4HeaderReadableWithoutDecrypt(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := encryptStreaming(t, sender, recipient, []byte("scriptable"), false, true) // public streaming (v4)

	sh, err := format.ParseStreamHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseStreamHeader: %v", err)
	}
	if sh.Profile != format.ProfilePublicStreaming || sh.Private {
		t.Fatalf("want public streaming profile, got %#x private=%v", byte(sh.Profile), sh.Private)
	}
	if sh.HeaderMeta.OriginalFilename != "test.bin" || sh.HeaderMeta.SenderFingerprint != sender.kp.Fingerprint {
		t.Fatalf("header metadata not readable without decrypting: %+v", sh.HeaderMeta)
	}
}

// TestV4TamperedSignature: a public-streaming container verifies against the
// header fingerprint; a tampered signature must not verify.
func TestV4TamperedSignature(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	data := encryptStreaming(t, sender, recipient, []byte("payload"), false, true) // public streaming

	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[len(tampered)-1] ^= 0xFF // last byte is inside the signature

	_, res := decryptV3(t, tampered, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if res.Status != VerifyUnverifiable {
		t.Fatalf("want Unverifiable for tampered v4 sig, got %+v", res)
	}
}

// TestProfileMatrixRoundTrip exercises all four profiles end-to-end through the
// high-level EncryptFile/DecryptFile — including the buffered write path — and
// pins the visibility contract: public profiles expose the filename on the wire,
// private profiles do not; all four round-trip and verify.
func TestProfileMatrixRoundTrip(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("round-trip across every profile")
	cases := []struct {
		name    string
		profile format.Profile
	}{
		{"public-buffered", format.ProfilePublicBuffered},
		{"private-buffered", format.ProfilePrivateBuffered},
		{"private-streaming", format.ProfilePrivateStreaming},
		{"public-streaming", format.ProfilePublicStreaming},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			inPath := filepath.Join(dir, "in.bin")
			encPath := filepath.Join(dir, "in.icfx")
			outPath := filepath.Join(dir, "out.bin")
			if err := os.WriteFile(inPath, file, 0o600); err != nil {
				t.Fatal(err)
			}
			meta := format.Metadata{SenderFingerprint: sender.kp.Fingerprint, OriginalFilename: "in.bin", IsSigned: true}
			if err := encrypt.EncryptFile(inPath, encPath, []string{recipient.kp.EncryptionRecipient}, sender.u, meta, c.profile); err != nil {
				t.Fatalf("EncryptFile: %v", err)
			}

			enc, err := os.ReadFile(encPath)
			if err != nil {
				t.Fatal(err)
			}
			if enc[4] != byte(c.profile) {
				t.Fatalf("wire profile byte = %#x, want %#x", enc[4], byte(c.profile))
			}
			if c.profile.Public() && !bytes.Contains(enc, []byte("in.bin")) {
				t.Fatal("public profile should expose the filename in the header")
			}
			if !c.profile.Public() && bytes.Contains(enc, []byte("in.bin")) {
				t.Fatal("private profile leaked the filename")
			}

			res, err := DecryptFile(encPath, outPath, recipient.u, []contacts.Contact{contactFor("alice", sender)})
			if err != nil {
				t.Fatalf("DecryptFile: %v", err)
			}
			if res.Status != VerifyOK || res.SignerAlias != "alice" {
				t.Fatalf("want OK via alice, got %+v", res)
			}
			out, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, file) {
				t.Fatal("round-trip plaintext mismatch")
			}
		})
	}
}

// zeroReader yields n bytes of zeros cheaply (no big allocation).
type zeroReader struct{ n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	k := int64(len(p))
	if k > z.n {
		k = z.n
	}
	for i := int64(0); i < k; i++ {
		p[i] = 0
	}
	z.n -= k
	return int(k), nil
}

// TestV3ConstantMemory proves the point of v3: encrypting AND decrypting a file
// far larger than any reasonable buffer keeps live heap bounded (streaming),
// never holding the whole file in RAM. If either side buffered the file, peak
// heap would approach the file size and blow the threshold.
func TestV3ConstantMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-file memory test in -short mode")
	}
	const size = int64(128) << 20 // 128 MiB
	// Streaming keeps live heap at baseline + a little GC garbage (tens of MiB);
	// buffering the file would push it to >=128 MiB. 96 MiB cleanly separates the
	// two without being sensitive to GC pacing.
	const heapLimit = uint64(96) << 20

	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.bin")
	encPath := filepath.Join(dir, "in.icfx")
	outPath := filepath.Join(dir, "out.bin")

	in, err := os.Create(inPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(in, &zeroReader{n: size}, size); err != nil {
		t.Fatal(err)
	}
	in.Close()

	// Sample peak live heap while streaming.
	var maxHeap atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				for {
					cur := maxHeap.Load()
					if m.HeapAlloc <= cur || maxHeap.CompareAndSwap(cur, m.HeapAlloc) {
						break
					}
				}
				time.Sleep(3 * time.Millisecond)
			}
		}
	}()

	meta := format.Metadata{SenderFingerprint: sender.kp.Fingerprint, OriginalFilename: "in.bin", IsSigned: true}
	if err := encrypt.EncryptFile(inPath, encPath, []string{recipient.kp.EncryptionRecipient}, sender.u, meta, format.ProfilePrivateStreaming); err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	res, err := DecryptFile(encPath, outPath, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}

	close(stop)
	wg.Wait()

	if res.Status != VerifyOK {
		t.Fatalf("want VerifyOK, got %+v", res)
	}
	fi, err := os.Stat(outPath)
	if err != nil || fi.Size() != size {
		t.Fatalf("output size = %v (err %v), want %d", fi.Size(), err, size)
	}
	if peak := maxHeap.Load(); peak > heapLimit {
		t.Fatalf("peak heap %d MiB exceeded limit %d MiB — likely buffering the whole file",
			peak>>20, heapLimit>>20)
	}
}
