//go:build pcsc && !android && !ios && !nohw

package chalresp

// PC/SC backend: HMAC-SHA1 challenge-response over CCID via the Yubico OATH
// applet. Covers Nitrokey 3 (its Trussed "Secrets App" reimplements the applet)
// and YubiKey-over-CCID. Opt-in via `-tags pcsc` because it needs a PC/SC stack
// (PCSC.framework on macOS, WinSCard on Windows — both system; libpcsclite +
// pcscd on Linux).
//
// Wire sequence verified against KeePassXC's YubiKeyInterfacePCSC:
//
//	SELECT   00 A4 04 00 07 A0 00 00 05 27 21 01   (OATH AID; also try …27 20 01)
//	HMAC     00 01 38 00 40 <64-byte padded challenge>   (P1=0x38 slot 2)
//	response 20-byte HMAC-SHA1 + SW 90 00; on 61 xx, GET RESPONSE 00 C0 00 00 xx
//
// STATUS: implemented to the verified spec but UNTESTED without a Nitrokey 3.
// The exact challenge padding the applet hashes (it does NOT strip like the OTP
// slot's HMAC_LT64) must be confirmed against real hardware before relying on it
// for cross-tool interop; for icfx's own seal+unlock it only needs determinism.

import (
	"fmt"
	"strings"

	"github.com/ebfe/scard"
)

// Yubico OATH applet AIDs. KeePassXC tries both; a device answering either can
// do HMAC challenge-response. 2721 01 is the OATH AID (Nitrokey 3 + YubiKey);
// 2720 01 is the legacy YubiKey AID.
var oathAIDs = [][]byte{
	{0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01},
	{0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01},
}

const insAPIReq = 0x01 // YubiKey/OATH HMAC command class instruction
// (APDU status words + GET RESPONSE caps live in chalresp.go with transmitChain.)

// pcscList enumerates PC/SC readers whose card answers an OATH-applet SELECT.
func pcscList() ([]DeviceDescriptor, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, nil // no PC/SC service ⇒ no devices (non-fatal)
	}
	defer ctx.Release()

	readers, err := ctx.ListReaders()
	if err != nil || len(readers) == 0 {
		return nil, nil
	}
	var out []DeviceDescriptor
	for _, reader := range readers {
		card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
		if err != nil {
			continue // no card / in use
		}
		_, selErr := selectOATH(card)
		card.Disconnect(scard.LeaveCard)
		if selErr != nil {
			continue // not an OATH/HMAC-capable card
		}
		out = append(out, DeviceDescriptor{
			Family:  familyForReader(reader),
			backend: backendPCSC,
			reader:  reader,
		})
	}
	return out, nil
}

// pcscIsSlot2Programmed reports whether the card can perform slot-2 HMAC. The
// OATH applet has no separate "is slot 2 valid" query like the OTP status
// report; a device that SELECTs the applet is treated as capable (the actual
// Challenge surfaces a clear error if the credential is absent).
func pcscIsSlot2Programmed(desc DeviceDescriptor) (bool, error) {
	return withCard(desc, func(card *scard.Card) (bool, error) {
		if _, err := selectOATH(card); err != nil {
			return false, err
		}
		return true, nil
	})
}

// pcscChallenge runs slot-2 HMAC-SHA1 over CCID and returns the 20-byte HMAC.
func pcscChallenge(desc DeviceDescriptor, challenge []byte) ([]byte, error) {
	var resp []byte
	_, err := withCard(desc, func(card *scard.Card) (struct{}, error) {
		if _, err := selectOATH(card); err != nil {
			return struct{}{}, err
		}
		r, err := sendHMAC(card, slotChalHMAC2, challenge)
		if err != nil {
			return struct{}{}, err
		}
		resp = r
		return struct{}{}, nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// withCard connects to the descriptor's reader, runs fn, and disconnects.
func withCard[T any](desc DeviceDescriptor, fn func(*scard.Card) (T, error)) (T, error) {
	var zero T
	ctx, err := scard.EstablishContext()
	if err != nil {
		return zero, fmt.Errorf("chalresp: PC/SC unavailable: %w", err)
	}
	defer ctx.Release()

	reader := desc.reader
	if reader == "" {
		readers, err := ctx.ListReaders()
		if err != nil || len(readers) == 0 {
			return zero, ErrNoDevice
		}
		reader = readers[0]
	}
	card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		return zero, fmt.Errorf("chalresp: connecting to %q: %w", reader, err)
	}
	defer card.Disconnect(scard.LeaveCard)
	// Bracket the SELECT→HMAC sequence in a transaction so a concurrent local
	// process (ykman/KeePassXC/PIV tool sharing the card) can't swap the selected
	// applet underneath us and feed a wrong response into the KEK. Keeps
	// ShareShared (coexistence) while making our two-APDU atom exclusive.
	if err := card.BeginTransaction(); err != nil {
		return zero, fmt.Errorf("chalresp: begin card transaction: %w", err)
	}
	defer card.EndTransaction(scard.LeaveCard)
	return fn(card)
}

// selectOATH tries each known OATH AID until one is accepted (SW 90 00).
func selectOATH(card *scard.Card) ([]byte, error) {
	var lastErr error
	for _, aid := range oathAIDs {
		apdu := append([]byte{0x00, 0xa4, 0x04, 0x00, byte(len(aid))}, aid...)
		data, err := transmitFull(card, apdu)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrNoDevice
	}
	return nil, lastErr
}

// sendHMAC issues the HMAC challenge-response APDU for the given slot command
// (0x38 slot 2 / 0x30 slot 1) and returns the 20-byte response.
func sendHMAC(card *scard.Card, slot byte, challenge []byte) ([]byte, error) {
	payload := padChallenge(challenge) // 64 bytes, yubikit rule
	apdu := append([]byte{0x00, insAPIReq, slot, 0x00, byte(len(payload))}, payload[:]...)
	data, err := transmitFull(card, apdu)
	if err != nil {
		return nil, err
	}
	// The OATH HMAC command returns EXACTLY a 20-byte HMAC-SHA1 (+ SW). Require
	// that and fail closed on anything else rather than silently truncating —
	// if a real Nitrokey 3 wraps the response, validate + adjust against
	// hardware before trusting this path.
	if len(data) != hmacLen {
		wipe(data)
		return nil, fmt.Errorf("chalresp: unexpected HMAC response length %d (want %d; slot empty or wrong config?)", len(data), hmacLen)
	}
	resp := append([]byte(nil), data...)
	wipe(data) // clear the intermediate secret buffer; caller wipes the returned copy
	return resp, nil
}

// transmitFull sends an APDU over the card, following "61 xx" GET RESPONSE
// chaining via the bounded, transport-agnostic transmitChain helper.
func transmitFull(card *scard.Card, apdu []byte) ([]byte, error) {
	return transmitChain(card.Transmit, apdu)
}

// familyForReader guesses the device family from the PC/SC reader name (used
// only for display; matching is by AID at Challenge time).
func familyForReader(reader string) string {
	r := strings.ToLower(reader)
	switch {
	case strings.Contains(r, "nitrokey"):
		return "nitrokey"
	case strings.Contains(r, "yubikey") || strings.Contains(r, "yubico"):
		return "yubikey"
	default:
		return "pcsc"
	}
}
