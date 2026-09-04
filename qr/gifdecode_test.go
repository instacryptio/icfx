package qr

import (
	"bytes"
	"image"
	"image/color"
	"image/gif"
	"testing"
)

func TestDecodeAnimatedQRGIF_RoundTrip(t *testing.T) {
	bundle := maxSizeBundle()
	gifBytes, err := GenerateAnimatedQRGIF(bundle, 512, DefaultFrameDelay)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecodeAnimatedQRGIF(gifBytes)
	if err != nil {
		t.Fatalf("DecodeAnimatedQRGIF: %v", err)
	}
	assertBundleEqual(t, got, bundle)
}

func TestDecodeAnimatedQRGIF_RoundTripSmall(t *testing.T) {
	bundle := maxSizeBundle()
	gifBytes, err := GenerateAnimatedQRGIF(bundle, 256, DefaultFrameDelay)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecodeAnimatedQRGIF(gifBytes)
	if err != nil {
		t.Fatalf("DecodeAnimatedQRGIF (256px): %v", err)
	}
	assertBundleEqual(t, got, bundle)
}

func TestDecodeAnimatedQRGIF_RoundTripSingleFrame(t *testing.T) {
	bundle := LockBundle{Name: "tiny", Fingerprint: "fp"}
	gifBytes, err := GenerateAnimatedQRGIF(bundle, 512, DefaultFrameDelay)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecodeAnimatedQRGIF(gifBytes)
	if err != nil {
		t.Fatalf("DecodeAnimatedQRGIF (single frame): %v", err)
	}
	assertBundleEqual(t, got, bundle)
}

func TestDecodeAnimatedQRGIF_NotGIF(t *testing.T) {
	if _, err := DecodeAnimatedQRGIF([]byte("not a gif at all")); err == nil {
		t.Fatal("non-GIF input must error")
	}
}

func TestDecodeAnimatedQRGIF_Truncated(t *testing.T) {
	gifBytes, err := GenerateAnimatedQRGIF(maxSizeBundle(), 256, DefaultFrameDelay)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAnimatedQRGIF(gifBytes[:len(gifBytes)/3]); err == nil {
		t.Fatal("truncated GIF must error")
	}
}

func TestDecodeAnimatedQRGIF_NoQRFrames(t *testing.T) {
	// A syntactically valid GIF whose frames carry no QR codes.
	blank := image.NewPaletted(image.Rect(0, 0, 64, 64), color.Palette{color.White, color.Black})
	anim := &gif.GIF{
		Image: []*image.Paletted{blank, blank},
		Delay: []int{10, 10},
	}
	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, anim); err != nil {
		t.Fatal(err)
	}

	_, err := DecodeAnimatedQRGIF(buf.Bytes())
	if err == nil {
		t.Fatal("GIF without QR frames must error")
	}
}

func TestDecodeAnimatedQRGIF_TooLarge(t *testing.T) {
	data := make([]byte, maxGIFBytes+1)
	copy(data, "GIF89a")
	if _, err := DecodeAnimatedQRGIF(data); err == nil {
		t.Fatal("oversized GIF must be rejected")
	}
}

func TestDecodeAnimatedQRGIF_TooManyFrames(t *testing.T) {
	pal := color.Palette{color.White, color.Black}
	anim := &gif.GIF{}
	for i := 0; i < maxGIFFrames+1; i++ {
		anim.Image = append(anim.Image, image.NewPaletted(image.Rect(0, 0, 1, 1), pal))
		anim.Delay = append(anim.Delay, 0)
	}
	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, anim); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAnimatedQRGIF(buf.Bytes()); err == nil {
		t.Fatal("GIF with too many frames must be rejected")
	}
}

func TestDecodeAnimatedQRGIF_HugeDimensions(t *testing.T) {
	// Hand-crafted header: GIF89a + logical screen 65535x65535, no GCT.
	data := append([]byte("GIF89a"), 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00)
	if _, err := DecodeAnimatedQRGIF(data); err == nil {
		t.Fatal("huge-canvas GIF must be rejected")
	}
}

func TestIsGIF(t *testing.T) {
	gifBytes, err := GenerateAnimatedQRGIF(LockBundle{Name: "x", Fingerprint: "fp"}, 256, DefaultFrameDelay)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"generated GIF", gifBytes, true},
		{"GIF87a header", []byte("GIF87a...."), true},
		{"PNG magic", []byte("\x89PNG\r\n\x1a\n"), false},
		{"armored lock", []byte("-----BEGIN ICFX LOCK-----"), false},
		{"JSON", []byte(`{"name":"x"}`), false},
		{"empty", nil, false},
	}
	for _, tc := range cases {
		if got := IsGIF(tc.data); got != tc.want {
			t.Errorf("%s: IsGIF got %v, want %v", tc.name, got, tc.want)
		}
	}
}
