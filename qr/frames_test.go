package qr

import (
	"bytes"
	"encoding/json"
	"errors"
	"image/gif"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// frameCapacityV15M is the QR version 15 byte-mode capacity at EC level M.
// Every animated frame payload must fit so frames stay small and scannable.
const frameCapacityV15M = 412

func maxSizeBundle() LockBundle {
	return LockBundle{
		ID:          "IC-abc123",
		Name:        "testuser",
		EncPubKey:   "age1pq1" + strings.Repeat("q", 1940), // hybrid recipient ~1946 chars
		SignPubKey:  strings.Repeat("A", 2604),             // ML-DSA-65 ~2604 chars base64
		Fingerprint: strings.Repeat("a", 16),
		Email:       "user@example.com",
		Alias:       "tester",
	}
}

func TestMarshalAnimatedQR_FrameSizeAndCount(t *testing.T) {
	bundle := maxSizeBundle()
	data, err := MarshalLockBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	payloads, err := MarshalAnimatedQR(bundle)
	if err != nil {
		t.Fatalf("MarshalAnimatedQR: %v", err)
	}

	wantCount := (len(data) + DefaultFrameChunkSize - 1) / DefaultFrameChunkSize
	if len(payloads) != wantCount {
		t.Errorf("frame count: got %d, want %d", len(payloads), wantCount)
	}

	seen := make(map[int]bool)
	var bid string
	for i, payload := range payloads {
		if len(payload) > frameCapacityV15M {
			t.Errorf("frame %d is %d bytes, exceeds QR v15-M capacity %d", i+1, len(payload), frameCapacityV15M)
		}
		var frame Frame
		if err := json.Unmarshal(payload, &frame); err != nil {
			t.Fatalf("frame %d unmarshal: %v", i+1, err)
		}
		if frame.Version != FrameVersion {
			t.Errorf("frame %d version: got %d, want %d", i+1, frame.Version, FrameVersion)
		}
		if frame.Total != wantCount {
			t.Errorf("frame %d total: got %d, want %d", i+1, frame.Total, wantCount)
		}
		if seen[frame.Index] {
			t.Errorf("duplicate frame index %d", frame.Index)
		}
		seen[frame.Index] = true
		if bid == "" {
			bid = frame.BundleID
		}
		if frame.BundleID != bid {
			t.Errorf("frame %d bundle ID %q differs from %q", i+1, frame.BundleID, bid)
		}
	}
	for i := 1; i <= wantCount; i++ {
		if !seen[i] {
			t.Errorf("missing frame index %d", i)
		}
	}

	t.Logf("%d frames, largest payload ≤ %d bytes (v15-M capacity %d)", len(payloads), frameCapacityV15M, frameCapacityV15M)
}

func collectAll(t *testing.T, c *FrameCollector, payloads [][]byte) Progress {
	t.Helper()
	var progress Progress
	for i, payload := range payloads {
		p, err := c.Add(payload)
		if err != nil {
			t.Fatalf("Add frame %d: %v", i+1, err)
		}
		if p.Received < progress.Received {
			t.Errorf("progress went backwards: %d after %d", p.Received, progress.Received)
		}
		progress = p
	}
	return progress
}

func assertBundleEqual(t *testing.T, got, want LockBundle) {
	t.Helper()
	if got != want {
		t.Errorf("reassembled bundle mismatch:\ngot  %+v\nwant %+v", got, want)
	}
}

func TestFrameCollector_RoundTrip_InOrder(t *testing.T) {
	bundle := maxSizeBundle()
	payloads, err := MarshalAnimatedQR(bundle)
	if err != nil {
		t.Fatal(err)
	}

	c := NewFrameCollector()
	progress := collectAll(t, c, payloads)
	if progress.Received != progress.Total || progress.Total != len(payloads) {
		t.Fatalf("progress: %+v, want %d/%d", progress, len(payloads), len(payloads))
	}
	if !c.Complete() {
		t.Fatal("collector should be complete")
	}

	got, err := c.Bundle()
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	assertBundleEqual(t, got, bundle)
}

func TestFrameCollector_RoundTrip_Reversed(t *testing.T) {
	bundle := maxSizeBundle()
	payloads, err := MarshalAnimatedQR(bundle)
	if err != nil {
		t.Fatal(err)
	}
	reversed := make([][]byte, len(payloads))
	for i, p := range payloads {
		reversed[len(payloads)-1-i] = p
	}

	c := NewFrameCollector()
	collectAll(t, c, reversed)
	got, err := c.Bundle()
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	assertBundleEqual(t, got, bundle)
}

func TestFrameCollector_RoundTrip_Shuffled(t *testing.T) {
	bundle := maxSizeBundle()
	payloads, err := MarshalAnimatedQR(bundle)
	if err != nil {
		t.Fatal(err)
	}
	shuffled := make([][]byte, len(payloads))
	copy(shuffled, payloads)
	rng := rand.New(rand.NewSource(42))
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	c := NewFrameCollector()
	collectAll(t, c, shuffled)
	got, err := c.Bundle()
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	assertBundleEqual(t, got, bundle)
}

func TestFrameCollector_DuplicateFramesIdempotent(t *testing.T) {
	payloads, err := MarshalAnimatedQR(maxSizeBundle())
	if err != nil {
		t.Fatal(err)
	}

	c := NewFrameCollector()
	if _, err := c.Add(payloads[0]); err != nil {
		t.Fatal(err)
	}
	p, err := c.Add(payloads[0])
	if err != nil {
		t.Fatalf("identical duplicate must not error: %v", err)
	}
	if p.Received != 1 {
		t.Errorf("duplicate changed Received: got %d, want 1", p.Received)
	}
}

func TestFrameCollector_NotFrame(t *testing.T) {
	rawBundle, err := MarshalLockBundle(maxSizeBundle())
	if err != nil {
		t.Fatal(err)
	}

	// The removed paired format's QRPart JSON has no "v" key — old dual-QR
	// scans must yield ErrNotFrame, not corrupt the collector.
	legacyPairedPart := []byte(`{"p":1,"n":2,"bid":"a1b2c3d4","d":{"name":"old","enc_pub_key":"age1pq1x"}}`)

	cases := map[string][]byte{
		"legacy paired part": legacyPairedPart,
		"raw bundle JSON":    rawBundle,
		"garbage":            []byte("definitely not json"),
		"armored text":       []byte("-----BEGIN ICFX LOCK-----\nabc\n-----END ICFX LOCK-----"),
	}
	for name, payload := range cases {
		c := NewFrameCollector()
		_, err := c.Add(payload)
		if !errors.Is(err, ErrNotFrame) {
			t.Errorf("%s: got %v, want ErrNotFrame", name, err)
		}
	}
}

func TestFrameCollector_UnsupportedVersion(t *testing.T) {
	payload := []byte(`{"v":2,"bid":"a1b2c3d4","p":1,"n":3,"d":"aGVsbG8="}`)
	c := NewFrameCollector()
	_, err := c.Add(payload)
	if err == nil || errors.Is(err, ErrNotFrame) {
		t.Fatalf("v2 frame must fail with a version error, got %v", err)
	}
	if !strings.Contains(err.Error(), "unsupported frame version 2") {
		t.Errorf("error should name the version: %v", err)
	}
}

func TestFrameCollector_RestartOnNewBundleID(t *testing.T) {
	bundleA := maxSizeBundle()
	bundleB := maxSizeBundle()
	bundleB.Name = "otheruser"

	framesA, err := MarshalAnimatedQR(bundleA)
	if err != nil {
		t.Fatal(err)
	}
	framesB, err := MarshalAnimatedQR(bundleB)
	if err != nil {
		t.Fatal(err)
	}

	c := NewFrameCollector()
	for _, p := range framesA[:3] {
		if _, err := c.Add(p); err != nil {
			t.Fatal(err)
		}
	}

	// First B frame restarts the collection.
	p, err := c.Add(framesB[0])
	if err != nil {
		t.Fatalf("Add first B frame: %v", err)
	}
	if p.Received != 1 {
		t.Errorf("restart: Received got %d, want 1", p.Received)
	}

	collectAll(t, c, framesB[1:])
	got, err := c.Bundle()
	if err != nil {
		t.Fatalf("Bundle: %v", err)
	}
	assertBundleEqual(t, got, bundleB)
}

func TestFrameCollector_CorruptStream(t *testing.T) {
	payloads, err := MarshalAnimatedQR(maxSizeBundle())
	if err != nil {
		t.Fatal(err)
	}
	var first Frame
	if err := json.Unmarshal(payloads[0], &first); err != nil {
		t.Fatal(err)
	}

	mutate := func(f func(*Frame)) []byte {
		frame := first
		f(&frame)
		out, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	t.Run("total mismatch", func(t *testing.T) {
		c := NewFrameCollector()
		if _, err := c.Add(payloads[0]); err != nil {
			t.Fatal(err)
		}
		bad := mutate(func(f *Frame) { f.Index = 2; f.Total = first.Total + 1 })
		if _, err := c.Add(bad); err == nil {
			t.Error("conflicting total must error")
		}
	})

	t.Run("index conflict", func(t *testing.T) {
		c := NewFrameCollector()
		if _, err := c.Add(payloads[0]); err != nil {
			t.Fatal(err)
		}
		bad := mutate(func(f *Frame) { f.Data = append(bytes.Clone(f.Data[:len(f.Data)-1]), f.Data[len(f.Data)-1]^0xFF) })
		if _, err := c.Add(bad); err == nil {
			t.Error("same index with different data must error")
		}
	})

	t.Run("index out of range", func(t *testing.T) {
		c := NewFrameCollector()
		bad := mutate(func(f *Frame) { f.Index = f.Total + 1 })
		if _, err := c.Add(bad); err == nil {
			t.Error("out-of-range index must error")
		}
		bad = mutate(func(f *Frame) { f.Index = 0 })
		if _, err := c.Add(bad); err == nil {
			t.Error("zero index must error")
		}
	})

	t.Run("missing bundle ID", func(t *testing.T) {
		c := NewFrameCollector()
		bad := mutate(func(f *Frame) { f.BundleID = "" })
		if _, err := c.Add(bad); err == nil {
			t.Error("missing bundle ID must error")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		c := NewFrameCollector()
		bad := mutate(func(f *Frame) { f.Data = nil })
		if _, err := c.Add(bad); err == nil {
			t.Error("empty data must error")
		}
	})
}

func TestFrameCollector_IntegrityFailure(t *testing.T) {
	payloads, err := MarshalAnimatedQR(maxSizeBundle())
	if err != nil {
		t.Fatal(err)
	}

	// Forge a consistent-looking frame: valid base64, right length, wrong bytes.
	var tampered Frame
	if err := json.Unmarshal(payloads[1], &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Data = bytes.Clone(tampered.Data)
	tampered.Data[10] ^= 0xFF
	forged, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}

	c := NewFrameCollector()
	for i, p := range payloads {
		if i == 1 {
			p = forged
		}
		if _, err := c.Add(p); err != nil {
			t.Fatalf("Add frame %d: %v", i+1, err)
		}
	}
	if !c.Complete() {
		t.Fatal("collector should report complete")
	}
	if _, err := c.Bundle(); err == nil {
		t.Fatal("tampered chunk must fail bundle ID verification")
	}
}

func TestFrameCollector_BundleIncomplete(t *testing.T) {
	payloads, err := MarshalAnimatedQR(maxSizeBundle())
	if err != nil {
		t.Fatal(err)
	}
	c := NewFrameCollector()
	if _, err := c.Add(payloads[0]); err != nil {
		t.Fatal(err)
	}
	if c.Complete() {
		t.Error("one frame must not be complete")
	}
	if _, err := c.Bundle(); err == nil {
		t.Error("Bundle on incomplete collector must error")
	}
}

func TestClassifyPayload(t *testing.T) {
	bundle := maxSizeBundle()
	frames, err := MarshalAnimatedQR(bundle)
	if err != nil {
		t.Fatal(err)
	}
	rawBundle, err := MarshalLockBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		data []byte
		want PayloadKind
	}{
		{"animated frame", frames[0], PayloadFrame},
		{"future v2 frame", []byte(`{"v":2,"bid":"x","p":1,"n":9,"d":"aGk="}`), PayloadFrame},
		{"removed paired-format part", []byte(`{"p":1,"n":2,"bid":"a1b2c3d4","d":{"name":"old"}}`), PayloadRaw},
		{"raw bundle JSON", rawBundle, PayloadRaw},
		{"armored", []byte("-----BEGIN ICFX LOCK-----\nabc\n-----END ICFX LOCK-----"), PayloadRaw},
		{"garbage", []byte("nope"), PayloadRaw},
	}
	for _, tc := range cases {
		if got := ClassifyPayload(tc.data); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestGenerateAnimatedQRGIF(t *testing.T) {
	bundle := maxSizeBundle()
	payloads, err := MarshalAnimatedQR(bundle)
	if err != nil {
		t.Fatal(err)
	}

	gifBytes, err := GenerateAnimatedQRGIF(bundle, 512, DefaultFrameDelay)
	if err != nil {
		t.Fatalf("GenerateAnimatedQRGIF: %v", err)
	}

	decoded, err := gif.DecodeAll(bytes.NewReader(gifBytes))
	if err != nil {
		t.Fatalf("DecodeAll: %v", err)
	}
	if len(decoded.Image) != len(payloads) {
		t.Errorf("GIF frames: got %d, want %d", len(decoded.Image), len(payloads))
	}
	if decoded.LoopCount != 0 {
		t.Errorf("LoopCount: got %d, want 0 (infinite)", decoded.LoopCount)
	}
	wantDelay := int(DefaultFrameDelay / (10 * time.Millisecond))
	for i, d := range decoded.Delay {
		if d != wantDelay {
			t.Errorf("frame %d delay: got %d, want %d", i, d, wantDelay)
		}
	}
	first := decoded.Image[0].Bounds()
	for i, img := range decoded.Image {
		if img.Bounds() != first {
			t.Errorf("frame %d bounds %v differ from %v", i, img.Bounds(), first)
		}
		if len(img.Palette) <= 2 || len(img.Palette) > 256 {
			t.Errorf("frame %d palette size: got %d, want >2 (logo colors) and ≤256", i, len(img.Palette))
		}
	}

	// The IC logo sits on a white circle at the center of every frame. A
	// pixel inside the circle ring but outside the logo square must be
	// white — proving the overlay ran (without depending on logo colors).
	frame0 := decoded.Image[0]
	cx := first.Min.X + first.Dx()/2
	cy := first.Min.Y + first.Dy()/2
	logoSize := first.Dx() * animatedLogoPercent / 100
	if logoSize < 16 {
		logoSize = 16
	}
	circleRadius := logoSize/2 + 4
	r, g, b, _ := frame0.At(cx+circleRadius-2, cy).RGBA()
	if r != 0xffff || g != 0xffff || b != 0xffff {
		t.Errorf("expected white circle ring pixel at center offset, got rgba(%d,%d,%d)", r, g, b)
	}

	t.Logf("GIF: %d frames, %d bytes, %v bounds, %d-color palette", len(decoded.Image), len(gifBytes), first, len(decoded.Image[0].Palette))
}

func TestGenerateAnimatedQRGIF_MinDelayClamp(t *testing.T) {
	gifBytes, err := GenerateAnimatedQRGIF(maxSizeBundle(), 256, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := gif.DecodeAll(bytes.NewReader(gifBytes))
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range decoded.Delay {
		if d < 2 {
			t.Errorf("frame %d delay %d below clamp of 2", i, d)
		}
	}
}

func TestMarshalAnimatedQR_TinyBundle(t *testing.T) {
	bundle := LockBundle{Name: "tiny", Fingerprint: "fp"}
	payloads, err := MarshalAnimatedQR(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 1 {
		t.Fatalf("tiny bundle frames: got %d, want 1", len(payloads))
	}

	c := NewFrameCollector()
	if _, err := c.Add(payloads[0]); err != nil {
		t.Fatal(err)
	}
	got, err := c.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	assertBundleEqual(t, got, bundle)
}
