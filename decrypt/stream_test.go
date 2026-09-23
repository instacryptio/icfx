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
)

// TestLargerPayload round-trips a multi-MB payload to exercise the streaming
// path across several age chunks.
func TestLargerPayload(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := make([]byte, 5<<20) // 5 MiB
	if _, err := rand.Read(file); err != nil {
		t.Fatal(err)
	}
	data := encryptContainer(t, sender, recipient, file, format.ProfilePrivate, true)

	plain, res := decryptContainerBytes(t, data, recipient.u, []contacts.Contact{contactFor("alice", sender)})
	if !bytes.Equal(plain, file) {
		t.Fatal("large payload mismatch")
	}
	if res.Status != VerifyOK {
		t.Fatalf("want OK, got %+v", res)
	}
}

// TestFileRoundTrip exercises the path-based wrappers for both profiles and
// pins the visibility contract: only ProfilePublic exposes the filename.
func TestFileRoundTrip(t *testing.T) {
	sender, recipient := newParty(t, "sender"), newParty(t, "recipient")
	file := []byte("round-trip through the file API")
	for _, profile := range []format.Profile{format.ProfilePrivate, format.ProfilePublic} {
		dir := t.TempDir()
		inPath := filepath.Join(dir, "in.bin")
		encPath := filepath.Join(dir, "in.icfx")
		outPath := filepath.Join(dir, "out.bin")
		if err := os.WriteFile(inPath, file, 0o600); err != nil {
			t.Fatal(err)
		}
		meta := format.Metadata{OriginalFilename: "in.bin", IsSigned: true}
		if err := encrypt.EncryptFile(inPath, encPath, []string{recipient.kp.EncryptionRecipient}, sender.u, meta, profile); err != nil {
			t.Fatalf("EncryptFile: %v", err)
		}
		enc, err := os.ReadFile(encPath)
		if err != nil {
			t.Fatal(err)
		}
		if enc[4] != byte(profile) {
			t.Fatalf("wire profile byte = %#x, want %#x", enc[4], byte(profile))
		}
		if bytes.Contains(enc, []byte("in.bin")) != profile.Public() {
			t.Fatalf("profile %#x: filename visibility wrong", byte(profile))
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

// TestConstantMemory proves encrypting AND decrypting a file far larger than
// any reasonable buffer keeps live heap bounded — the digests over plaintext
// and ciphertext are computed on the way through, never by buffering.
func TestConstantMemory(t *testing.T) {
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

	meta := format.Metadata{OriginalFilename: "in.bin", IsSigned: true}
	if err := encrypt.EncryptFile(inPath, encPath, []string{recipient.kp.EncryptionRecipient}, sender.u, meta, format.ProfilePrivate); err != nil {
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
