package qr

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/color/palette"
	"image/draw"
	"image/gif"
	"sync"
	"time"

	goqrcode "github.com/skip2/go-qrcode"
)

// Animated Lock QR frame format (v1).
//
// A LockBundle too large for a single QR code is split into small sequential
// chunks, each carried by one QR frame of an animated (looping) sequence. A
// scanner accumulates frames in any order across loop cycles until all chunks
// arrived, then reassembles and integrity-checks the bundle.
//
// Each frame encodes compact UTF-8 JSON:
//
//	{"v":1,"bid":"a1b2c3d4","p":7,"n":19,"d":"<std-base64 chunk>"}
//
// The "v" key is the format discriminator: legacy paired QRPart JSON never
// carries it. Version 1 is plain sequential chunking; a future version may
// carry fountain-coded (rateless) chunks for large optical transfers, so
// decoders must reject unknown versions loudly rather than guess.

const (
	// FrameVersion is the animated frame format version this build produces.
	FrameVersion = 1

	// DefaultFrameChunkSize is the raw bundle bytes carried per frame.
	// 256 raw bytes → ≤388-byte frame JSON (44B fixed overhead + base64
	// expansion), which fits QR version ≤15 at EC level M (412-byte
	// byte-mode capacity). Small codes scan far more reliably from a
	// changing screen than the dense v30+ codes of the paired format.
	DefaultFrameChunkSize = 256

	// DefaultFrameDelay is the per-frame duration for animated QR output.
	DefaultFrameDelay = 300 * time.Millisecond
)

// ErrNotFrame reports that a payload is not an animated QR frame.
var ErrNotFrame = errors.New("not an animated QR frame")

// Frame is one animated Lock QR frame (v1: plain sequential chunk).
type Frame struct {
	Version  int    `json:"v"`
	BundleID string `json:"bid"`
	Index    int    `json:"p"` // 1-based
	Total    int    `json:"n"`
	Data     []byte `json:"d"` // std base64 on the wire
}

// MarshalAnimatedQR splits a LockBundle into v1 animated frame payloads.
// Each payload is the exact UTF-8 JSON one QR frame encodes.
func MarshalAnimatedQR(bundle LockBundle) ([][]byte, error) {
	data, err := MarshalLockBundle(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshaling bundle: %w", err)
	}

	bid, err := computeBundleID(bundle)
	if err != nil {
		return nil, err
	}

	total := (len(data) + DefaultFrameChunkSize - 1) / DefaultFrameChunkSize
	if total < 1 {
		return nil, fmt.Errorf("empty bundle")
	}

	payloads := make([][]byte, 0, total)
	for i := 0; i < total; i++ {
		start := i * DefaultFrameChunkSize
		end := start + DefaultFrameChunkSize
		if end > len(data) {
			end = len(data)
		}
		frame := Frame{
			Version:  FrameVersion,
			BundleID: bid,
			Index:    i + 1,
			Total:    total,
			Data:     data[start:end],
		}
		payload, err := json.Marshal(frame)
		if err != nil {
			return nil, fmt.Errorf("marshaling frame %d: %w", i+1, err)
		}
		payloads = append(payloads, payload)
	}

	return payloads, nil
}

// Progress reports frame accumulation state.
type Progress struct {
	Received int
	Total    int
}

// FrameCollector accumulates animated Lock QR frames in any order and
// reassembles the LockBundle once every chunk arrived. Safe for concurrent
// use. Frames belonging to a different bundle ID restart the collection —
// the scanner UX where the user re-aims at a different contact's animation
// simply begins a fresh accumulation.
type FrameCollector struct {
	mu     sync.Mutex
	bid    string
	total  int
	chunks map[int][]byte
}

// NewFrameCollector returns an empty collector.
func NewFrameCollector() *FrameCollector {
	return &FrameCollector{chunks: make(map[int][]byte)}
}

// Add ingests one scanned frame payload. Payloads that are not animated
// frames at all yield ErrNotFrame so callers can fall through to legacy
// import paths. Duplicate frames are idempotent.
func (c *FrameCollector) Add(payload []byte) (Progress, error) {
	var frame Frame
	if err := json.Unmarshal(payload, &frame); err != nil {
		return Progress{}, ErrNotFrame
	}
	if frame.Version == 0 {
		return Progress{}, ErrNotFrame
	}
	if frame.Version != FrameVersion {
		return Progress{}, fmt.Errorf("unsupported frame version %d (this build supports v%d)", frame.Version, FrameVersion)
	}
	if frame.BundleID == "" {
		return Progress{}, fmt.Errorf("frame missing bundle ID")
	}
	if frame.Total < 1 {
		return Progress{}, fmt.Errorf("invalid frame total %d", frame.Total)
	}
	if frame.Index < 1 || frame.Index > frame.Total {
		return Progress{}, fmt.Errorf("frame index %d out of range 1..%d", frame.Index, frame.Total)
	}
	if len(frame.Data) == 0 {
		return Progress{}, fmt.Errorf("frame %d has no data", frame.Index)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// A frame from a different bundle restarts the collection.
	if c.bid != "" && c.bid != frame.BundleID {
		c.resetLocked()
	}
	if c.bid == "" {
		c.bid = frame.BundleID
		c.total = frame.Total
	}
	if frame.Total != c.total {
		return Progress{}, fmt.Errorf("frame total %d conflicts with expected %d", frame.Total, c.total)
	}

	existing, ok := c.chunks[frame.Index]
	if ok && !bytes.Equal(existing, frame.Data) {
		return Progress{}, fmt.Errorf("frame %d conflicts with previously scanned data", frame.Index)
	}
	c.chunks[frame.Index] = frame.Data

	return Progress{Received: len(c.chunks), Total: c.total}, nil
}

// Complete reports whether every frame has been collected.
func (c *FrameCollector) Complete() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total > 0 && len(c.chunks) == c.total
}

// Bundle reassembles and integrity-checks the collected LockBundle.
func (c *FrameCollector) Bundle() (LockBundle, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.total == 0 || len(c.chunks) != c.total {
		return LockBundle{}, fmt.Errorf("incomplete: %d of %d frames collected", len(c.chunks), c.total)
	}

	var data []byte
	for i := 1; i <= c.total; i++ {
		data = append(data, c.chunks[i]...)
	}

	bundle, err := ParseLockBundle(data)
	if err != nil {
		return LockBundle{}, fmt.Errorf("reassembling bundle: %w", err)
	}

	bid, err := computeBundleID(bundle)
	if err != nil {
		return LockBundle{}, fmt.Errorf("computing verification bundle ID: %w", err)
	}
	if bid != c.bid {
		return LockBundle{}, fmt.Errorf("bundle ID verification failed: computed %q, expected %q", bid, c.bid)
	}

	return bundle, nil
}

// Reset discards all collected frames.
func (c *FrameCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetLocked()
}

func (c *FrameCollector) resetLocked() {
	c.bid = ""
	c.total = 0
	c.chunks = make(map[int][]byte)
}

// PayloadKind classifies scanned QR payloads for import routing.
type PayloadKind int

const (
	// PayloadRaw is anything that is not an animated frame: a raw lock
	// bundle (armored or plain JSON).
	PayloadRaw PayloadKind = iota
	// PayloadFrame is a v1+ animated QR frame.
	PayloadFrame
)

// ClassifyPayload inspects a scanned payload and reports which import path
// should handle it. It never errors: unrecognized data is PayloadRaw.
func ClassifyPayload(data []byte) PayloadKind {
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return PayloadRaw
	}
	if probe.V >= 1 {
		return PayloadFrame
	}
	return PayloadRaw
}

// animatedLogoPercent is the logo width (as % of frame width) on animated
// frames. The frames are sparse (≤v15) codes at EC level M (~15% recovery),
// so a prominently visible logo still obstructs only ~2% of modules.
const animatedLogoPercent = 12

// GenerateAnimatedQRGIF renders a LockBundle as an infinitely looping
// animated GIF of QR frames (EC level M, embedded IC logo).
func GenerateAnimatedQRGIF(bundle LockBundle, size int, frameDelay time.Duration) ([]byte, error) {
	payloads, err := MarshalAnimatedQR(bundle)
	if err != nil {
		return nil, err
	}

	// GIF delay is in 10ms units; clamp to 2 (renderers ignore <20ms).
	delay := int(frameDelay / (10 * time.Millisecond))
	if delay < 2 {
		delay = 2
	}

	anim := &gif.GIF{LoopCount: 0}

	// All frames share one small color set (black, white, logo colors), so
	// one palette-lookup cache serves the whole animation.
	cache := make(map[color.RGBA]uint8)

	for i, payload := range payloads {
		qrc, err := goqrcode.New(string(payload), goqrcode.Medium)
		if err != nil {
			return nil, fmt.Errorf("creating QR for frame %d: %w", i+1, err)
		}
		qrc.DisableBorder = false

		src := qrc.Image(size)
		bounds := src.Bounds()
		rgba := image.NewRGBA(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
		draw.Draw(rgba, rgba.Bounds(), src, bounds.Min, draw.Src)

		if err := overlayLogo(rgba, animatedLogoPercent); err != nil {
			return nil, fmt.Errorf("overlaying logo on frame %d: %w", i+1, err)
		}

		// Plan9 (256 colors) keeps the logo's colors; the pure black/white
		// QR modules map exactly, so no dithering — error diffusion could
		// smear module edges.
		frame := palettedFromRGBA(rgba, palette.Plan9, cache)

		anim.Image = append(anim.Image, frame)
		anim.Delay = append(anim.Delay, delay)
	}

	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, anim); err != nil {
		return nil, fmt.Errorf("encoding animated QR GIF: %w", err)
	}

	return buf.Bytes(), nil
}

// palettedFromRGBA converts an RGBA image to a paletted one, memoizing the
// palette lookup per unique color. Naive conversion pays a linear scan over
// the whole palette for EVERY pixel; QR frames contain only a handful of
// distinct colors, so caching the index per color makes conversion cheap.
// The cache may be shared across images that draw from the same color set.
func palettedFromRGBA(rgba *image.RGBA, pal color.Palette, cache map[color.RGBA]uint8) *image.Paletted {
	bounds := rgba.Bounds()
	out := image.NewPaletted(bounds, pal)
	w := bounds.Dx()

	for y := 0; y < bounds.Dy(); y++ {
		srcRow := rgba.Pix[y*rgba.Stride : y*rgba.Stride+w*4]
		dstRow := out.Pix[y*out.Stride : y*out.Stride+w]
		for x := 0; x < w; x++ {
			c := color.RGBA{srcRow[x*4], srcRow[x*4+1], srcRow[x*4+2], srcRow[x*4+3]}
			idx, ok := cache[c]
			if !ok {
				idx = uint8(pal.Index(c))
				cache[c] = idx
			}
			dstRow[x] = idx
		}
	}

	return out
}
