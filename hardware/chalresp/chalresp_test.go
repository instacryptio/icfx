//go:build !android && !ios && !nohw

package chalresp

import (
	"bytes"
	"testing"
)

// TestCRC16Residual verifies the two CRC conventions the protocol uses:
//   - WRITE frame (buildFrame): the CRC is stored un-complemented, exactly as
//     ykpers' yk_write_to_key does, so CRC-over-(payload||crc) self-cancels to 0.
//   - RESPONSE (crcValid): the device stores the COMPLEMENTED CRC (the OTP-token
//     / X.25 convention), giving residual YK_CRC_OK_RESIDUAL (0xF0B8) — which is
//     what yk_read_response_from_key (and crcValid) check.
func TestCRC16Residual(t *testing.T) {
	cases := [][]byte{
		{0x01, 0x02, 0x03, 0x04},
		make([]byte, 20), // 20-byte HMAC response length
		{0xde, 0xad, 0xbe, 0xef},
		bytes.Repeat([]byte{0xAB}, 64),
	}
	for _, data := range cases {
		crc := yubikeyCRC16(data)

		writeFrame := append(append([]byte{}, data...), byte(crc&0xff), byte(crc>>8))
		if got := yubikeyCRC16(writeFrame); got != 0 {
			t.Fatalf("write-frame residual for %x = 0x%04x, want 0x0000", data, got)
		}

		comp := crc ^ 0xffff
		response := append(append([]byte{}, data...), byte(comp&0xff), byte(comp>>8))
		if got := yubikeyCRC16(response); got != crcResidual {
			t.Fatalf("response residual for %x = 0x%04x, want 0x%04x", data, got, crcResidual)
		}
		if !crcValid(response) {
			t.Fatalf("crcValid(response) = false for %x", data)
		}
	}
}

// TestCRC16KnownVector pins yubikeyCRC16 to a known-good value so a refactor
// can't silently change the polynomial/init. Verified against yubico-c's
// yubikey_crc16: CRC16(0x01) = 0x1e0e.
func TestCRC16KnownVector(t *testing.T) {
	if got := yubikeyCRC16([]byte{0x01}); got != 0x1e0e {
		t.Fatalf("CRC16(0x01) = 0x%04x, want 0x1e0e", got)
	}
}

// TestPadChallenge covers the yubikit "differ-from-last" padding rule.
func TestPadChallenge(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		wantPad byte // expected padding byte (only checked when len(in) < 64)
	}{
		{"short non-zero-ending", []byte{0x01, 0x02, 0x03}, 0x00},
		{"short zero-ending", []byte{0x01, 0x02, 0x00}, 0x01},
		{"32 non-zero-ending", append(bytes.Repeat([]byte{0x07}, 31), 0x09), 0x00},
		{"32 zero-ending", append(bytes.Repeat([]byte{0x07}, 31), 0x00), 0x01},
		{"empty", []byte{}, 0x00},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := padChallenge(c.in)
			if !bytes.Equal(p[:len(c.in)], c.in) {
				t.Fatalf("payload prefix = %x, want %x", p[:len(c.in)], c.in)
			}
			for i := len(c.in); i < frameDataSize; i++ {
				if p[i] != c.wantPad {
					t.Fatalf("pad byte at %d = 0x%02x, want 0x%02x", i, p[i], c.wantPad)
				}
			}
		})
	}
}

// TestPadChallengeFull64 confirms a 64-byte challenge is sent verbatim (no pad).
func TestPadChallengeFull64(t *testing.T) {
	in := bytes.Repeat([]byte{0x5a}, 64)
	in[63] = 0x00 // ends in 0x00, but full length ⇒ no padding at all
	p := padChallenge(in)
	if !bytes.Equal(p[:], in) {
		t.Fatalf("64-byte challenge altered: got %x", p[:])
	}
}

// TestBuildFrame checks the 70-byte frame layout: payload, slot byte, CRC (LE
// over the 64-byte payload), and zero filler.
func TestBuildFrame(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x11}, 32)
	frame := buildFrame(challenge, slotChalHMAC2)

	if !bytes.Equal(frame[:len(challenge)], challenge) {
		t.Fatalf("payload prefix wrong: %x", frame[:len(challenge)])
	}
	if frame[frameDataSize] != slotChalHMAC2 {
		t.Fatalf("slot byte = 0x%02x, want 0x%02x", frame[frameDataSize], slotChalHMAC2)
	}
	wantCRC := yubikeyCRC16(frame[:frameDataSize])
	gotCRC := uint16(frame[frameDataSize+1]) | uint16(frame[frameDataSize+2])<<8
	if gotCRC != wantCRC {
		t.Fatalf("frame CRC = 0x%04x, want 0x%04x (little-endian over payload)", gotCRC, wantCRC)
	}
	for i := frameDataSize + 3; i < frameSize; i++ {
		if frame[i] != 0 {
			t.Fatalf("filler byte %d = 0x%02x, want 0", i, frame[i])
		}
	}
}

// TestTransmitChainOK: single response + SW 9000.
func TestTransmitChainOK(t *testing.T) {
	calls := 0
	out, err := transmitChain(func([]byte) ([]byte, error) {
		calls++
		return []byte{0xde, 0xad, swOKHi, swOKLo}, nil
	}, []byte{0x00, 0xa4})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0xde, 0xad}) || calls != 1 {
		t.Fatalf("out=%x calls=%d", out, calls)
	}
}

// TestTransmitChainGetResponse: "61 xx" chaining concatenates the data.
func TestTransmitChainGetResponse(t *testing.T) {
	seq := 0
	out, err := transmitChain(func([]byte) ([]byte, error) {
		seq++
		if seq == 1 {
			return []byte{0xaa, swMore, 0x02}, nil // 1 data byte + "61 02"
		}
		return []byte{0xbb, 0xcc, swOKHi, swOKLo}, nil
	}, []byte{0x00, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("out=%x", out)
	}
}

// TestTransmitChainHangBounded: a card that returns bare "61 01" forever must
// error (bounded), not hang — the HIGH-severity DoS fix.
func TestTransmitChainHangBounded(t *testing.T) {
	calls := 0
	_, err := transmitChain(func([]byte) ([]byte, error) {
		calls++
		return []byte{swMore, 0x01}, nil // len 2: no data, "more"
	}, []byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error on an unbounded 61xx chain")
	}
	if calls > maxAPDUChain+1 {
		t.Fatalf("chain not bounded: %d calls", calls)
	}
}

// TestTransmitChainSizeBounded: a card flooding data must hit a cap and error.
func TestTransmitChainSizeBounded(t *testing.T) {
	_, err := transmitChain(func([]byte) ([]byte, error) {
		return append(make([]byte, 253), swMore, 0xff), nil
	}, []byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error on a flooding card")
	}
}

// TestTransmitChainErrorSW: a non-9000/61xx status word fails closed.
func TestTransmitChainErrorSW(t *testing.T) {
	if _, err := transmitChain(func([]byte) ([]byte, error) {
		return []byte{0x6a, 0x82}, nil // file/applet not found
	}, []byte{0x00, 0xa4}); err == nil {
		t.Fatal("expected an APDU error SW to fail")
	}
}
