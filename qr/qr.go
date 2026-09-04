// Package qr defines the LockBundle wire format for exchanging identity locks,
// plus the animated-QR (multi-frame GIF) encode/decode path for transferring a
// lock too large for a single QR code (MarshalAnimatedQR / FrameCollector /
// GenerateAnimatedQRGIF / DecodeAnimatedQRGIF). It also covers lock
// self-signing and verification — fingerprint-to-keys binding (VerifyFingerprint)
// and the lock self-signature (SealLock / VerifyLockSelfSig).
package qr

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg"
	"image/png"

	goqrcode "github.com/skip2/go-qrcode"
)

//go:embed logo.png
var logoData []byte

// LockBundle holds the public key data for lock export/import.
//
// Sig is a base64 ML-DSA-65 self-signature over the bundle's key-binding
// fields (see CanonicalLockBytes) made by the identity's own signing key. It
// proves the holder of SignPubKey asserts EncPubKey+Fingerprint as a unit and
// that the bundle was not tampered with in transit. See SealLock /
// VerifyLockSelfSig.
type LockBundle struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	EncPubKey   string `json:"enc_pub_key,omitempty"`
	SignPubKey  string `json:"sign_pub_key,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Email       string `json:"email,omitempty"`
	// Alias is the identity owner's self-set public handle (was "nickname"). An
	// advisory label — excluded from the self-signature (see CanonicalLockBytes)
	// so editing it never requires re-sealing.
	Alias string `json:"alias,omitempty"`
	Sig   string `json:"sig,omitempty"`
}

// MarshalLockBundle serializes a LockBundle to compact JSON.
func MarshalLockBundle(bundle LockBundle) ([]byte, error) {
	return json.Marshal(bundle)
}

// ParseLockBundle deserializes JSON into a LockBundle.
// Backward-compatible: old QR data without sign_pub_key results in empty string.
func ParseLockBundle(data []byte) (LockBundle, error) {
	var bundle LockBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return LockBundle{}, fmt.Errorf("parsing lock bundle: %w", err)
	}
	return bundle, nil
}

// computeBundleID computes an 8-char hex bundle ID from the full lock bundle JSON.
func computeBundleID(bundle LockBundle) (string, error) {
	data, err := json.Marshal(bundle)
	if err != nil {
		return "", fmt.Errorf("marshaling bundle for ID: %w", err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])[:8], nil
}

// GenerateQRPNG generates a QR code PNG at EC level L with an embedded logo.
// Level L is required to fit full lock bundles with the ML-DSA-65 SignPubKey (~2848 bytes)
// within QR v40 byte-mode capacity (2953 bytes). The logo covers ~2% of QR area,
// well within L-level's ~7% error correction tolerance.
func GenerateQRPNG(data string, size int) ([]byte, error) {
	qrc, err := goqrcode.New(data, goqrcode.Low)
	if err != nil {
		return nil, fmt.Errorf("creating QR code: %w", err)
	}
	qrc.DisableBorder = false

	qrPNG, err := qrc.PNG(size)
	if err != nil {
		return nil, fmt.Errorf("encoding QR PNG: %w", err)
	}

	qrImg, err := png.Decode(bytes.NewReader(qrPNG))
	if err != nil {
		return nil, fmt.Errorf("decoding QR image: %w", err)
	}

	bounds := qrImg.Bounds()
	result := image.NewRGBA(bounds)
	draw.Draw(result, bounds, qrImg, bounds.Min, draw.Src)

	if err := overlayLogo(result, staticLogoPercent); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, result); err != nil {
		return nil, fmt.Errorf("encoding result PNG: %w", err)
	}

	return buf.Bytes(), nil
}

// staticLogoPercent is the logo width (as % of image width) on dense static
// QR codes (v30-v40 at EC level L, ~7% recovery) — kept deliberately tiny.
const staticLogoPercent = 2

// overlayLogo draws the embedded IC logo, centered on a white circle, onto a
// rendered QR image. widthPercent is the logo width as a percentage of the
// image width (min 16px); callers size it to their code density and EC
// level's recovery budget.
func overlayLogo(img *image.RGBA, widthPercent int) error {
	logoImg, _, err := image.Decode(bytes.NewReader(logoData))
	if err != nil {
		return fmt.Errorf("decoding logo: %w", err)
	}

	bounds := img.Bounds()
	logoSize := bounds.Dx() * widthPercent / 100
	if logoSize < 16 {
		logoSize = 16
	}
	circleRadius := logoSize/2 + 4
	centerX := bounds.Min.X + bounds.Dx()/2
	centerY := bounds.Min.Y + bounds.Dy()/2

	// Draw white circle background
	for y := centerY - circleRadius; y <= centerY+circleRadius; y++ {
		for x := centerX - circleRadius; x <= centerX+circleRadius; x++ {
			dx := x - centerX
			dy := y - centerY
			if dx*dx+dy*dy <= circleRadius*circleRadius {
				img.Set(x, y, color.White)
			}
		}
	}

	// Scale and draw logo
	scaledLogo := scaleImage(logoImg, logoSize, logoSize)
	logoRect := image.Rect(
		centerX-logoSize/2, centerY-logoSize/2,
		centerX-logoSize/2+logoSize, centerY-logoSize/2+logoSize,
	)
	draw.Draw(img, logoRect, scaledLogo, scaledLogo.Bounds().Min, draw.Over)

	return nil
}

// scaleImage performs nearest-neighbor scaling of an image.
func scaleImage(src image.Image, width, height int) image.Image {
	srcBounds := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			srcX := srcBounds.Min.X + x*srcBounds.Dx()/width
			srcY := srcBounds.Min.Y + y*srcBounds.Dy()/height
			dst.Set(x, y, src.At(srcX, srcY))
		}
	}

	return dst
}

// RenderTerminalQR returns a scannable QR code for data as a compact string of
// Unicode half-block characters for printing to a terminal. It reuses
// go-qrcode's ToSmallString (no extra dependency) and is used to display an
// otpauth:// enrollment URL for scanning with an authenticator app.
func RenderTerminalQR(data string) (string, error) {
	qrc, err := goqrcode.New(data, goqrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("creating QR code: %w", err)
	}
	return qrc.ToSmallString(false), nil
}
