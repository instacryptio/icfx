package qr

import (
	"bytes"
	"fmt"
	"image/gif"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// Resource caps for decoding untrusted animated QR GIFs. A legitimate lock GIF
// is ~250 KB with ~19 small frames; these bounds leave generous headroom while
// preventing a decompression/dimension/frame bomb from exhausting memory or CPU.
const (
	maxGIFBytes  = 4 << 20     // reject inputs larger than 4 MiB outright
	maxGIFPixels = 4096 * 4096 // per the logical screen descriptor, before DecodeAll allocates
	maxGIFFrames = 64          // bounds the O(frames × hints × pixels) decode loop
)

// IsGIF reports whether data begins with a GIF87a/GIF89a header. Callers use
// it to detect animated QR GIFs by content rather than filename.
func IsGIF(data []byte) bool {
	return bytes.HasPrefix(data, []byte("GIF87a")) || bytes.HasPrefix(data, []byte("GIF89a"))
}

// DecodeAnimatedQRGIF decodes an animated Lock QR GIF back into its
// LockBundle: every GIF frame is QR-decoded, the frame payloads are
// accumulated in any order (duplicates are fine), and the reassembled bundle
// is integrity-checked against the embedded bundle ID. Individual frames
// that fail to decode are tolerated as long as every chunk is recovered.
func DecodeAnimatedQRGIF(data []byte) (LockBundle, error) {
	// Bound resources on untrusted input BEFORE the expensive decode. Input
	// size is the first gate; the logical-screen dimensions are checked from
	// the header (cheap) so a huge-canvas bomb is rejected before DecodeAll
	// allocates per-frame buffers.
	if len(data) > maxGIFBytes {
		return LockBundle{}, fmt.Errorf("GIF too large: %d bytes (max %d)", len(data), maxGIFBytes)
	}
	cfg, err := gif.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return LockBundle{}, fmt.Errorf("reading GIF header: %w", err)
	}
	// Compare in int64 so Width*Height can't overflow int (negative on 32-bit)
	// and slip past the pixel-bomb guard.
	if int64(cfg.Width)*int64(cfg.Height) > maxGIFPixels {
		return LockBundle{}, fmt.Errorf("GIF dimensions too large: %dx%d", cfg.Width, cfg.Height)
	}

	anim, err := gif.DecodeAll(bytes.NewReader(data))
	if err != nil {
		return LockBundle{}, fmt.Errorf("decoding GIF: %w", err)
	}
	if len(anim.Image) == 0 {
		return LockBundle{}, fmt.Errorf("GIF contains no frames")
	}
	if len(anim.Image) > maxGIFFrames {
		return LockBundle{}, fmt.Errorf("GIF has too many frames: %d (max %d)", len(anim.Image), maxGIFFrames)
	}

	reader := qrcode.NewQRCodeReader()
	// Generated GIF frames are pristine axis-aligned codes with clean quiet
	// zones, where PURE_BARCODE's direct grid sampling is the most reliable
	// path (the center logo can throw off the transform-estimating locator).
	// TRY_HARDER is the fallback for re-encoded or resized GIFs that break
	// pure mode's strict assumptions.
	hintSets := []map[gozxing.DecodeHintType]interface{}{
		{gozxing.DecodeHintType_PURE_BARCODE: true},
		{gozxing.DecodeHintType_TRY_HARDER: true},
	}

	collector := NewFrameCollector()
	decoded := 0

	for _, frame := range anim.Image {
		for _, hints := range hintSets {
			bmp, err := gozxing.NewBinaryBitmapFromImage(frame)
			if err != nil {
				break
			}
			result, err := reader.Decode(bmp, hints)
			if err != nil {
				continue
			}
			if _, err := collector.Add([]byte(result.GetText())); err != nil {
				break
			}
			decoded++
			break
		}
		if collector.Complete() {
			break
		}
	}

	if decoded == 0 {
		return LockBundle{}, fmt.Errorf("no QR frames decoded from GIF (%d frames scanned)", len(anim.Image))
	}
	if !collector.Complete() {
		return LockBundle{}, fmt.Errorf("incomplete animated QR: decoded %d usable frames from %d GIF frames", decoded, len(anim.Image))
	}

	return collector.Bundle()
}
