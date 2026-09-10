//go:build !android && !ios && !nohw

package chalresp

// HID backend: speaks the YubiKey OTP-over-HID challenge-response protocol
// directly, via hidapi (github.com/sstallion/go-hid). This covers YubiKey and
// OnlyKey (firmware >=2.1.0), whose firmware implements the identical wire
// protocol on the same HID keyboard interface. No libykpers, no libusb, no
// device-claiming — so it works on macOS/Windows/Linux without entitlements.
//
// Wire protocol verified against Yubico ykpers (ykcore/ykcore.c, ykdef.h),
// yubikit-core, and yubico-c's CRC (ykcrc.c); OnlyKey's firmware mirrors it
// byte-for-byte. All multi-byte fields are little-endian on the wire.

import (
	"errors"
	"fmt"
	"sync"
	"time"

	hid "github.com/sstallion/go-hid"
)

// --- USB identifiers for devices speaking the YubiKey OTP-HID protocol -------
const (
	vidYubico  = 0x1050 // Yubico — all OTP-capable YubiKeys
	vidOnlyKey = 0x1d50 // OpenMoko-assigned VID used by OnlyKey
	pidOnlyKey = 0x60fc // OnlyKey

	// The OTP challenge-response interface is the HID *keyboard* collection on
	// both YubiKey and OnlyKey — NOT the FIDO interface (usage page 0xf1d0).
	usagePageKeyboard = 0x0001 // Generic Desktop
	usageKeyboard     = 0x0006 // Keyboard
)

// --- OTP HID feature-report protocol constants (ykpers ykdef.h) --------------
const (
	featureRptSize = 8                  // 7 data bytes + 1 flags byte
	recordDataSize = featureRptSize - 1 // 7 payload bytes per report
	frameDataSize  = 64                 // SLOT_DATA_SIZE — challenge payload area
	frameSize      = 70                 // payload(64) + slot(1) + crc(2) + filler(3) = 10 records

	slotWriteFlag       = 0x80 // host sets on each write record; device clears when consumed
	respPendingFlag     = 0x40 // set on read reports carrying response bytes
	respTimeoutWaitFlag = 0x20 // device is waiting for a touch (secs in low 5 bits)
	dummyReport         = 0x8f // reset/abort flags byte (DUMMY_REPORT_WRITE)
	sequenceMask        = 0x1f // low 5 bits of the flags byte = sequence number

	slotChalHMAC2 = 0x38 // SLOT_CHAL_HMAC2 (slot 2) == `ykchalresp -2`

	statusTouchOffset = 0x05 // STATUS_OFFSET_TOUCH_LOW — CONFIG{1,2}_VALID live here
	config2Valid      = 0x02 // CONFIG2_VALID — slot 2 is programmed

	hmacLen     = 20     // SHA1_DIGEST_SIZE
	crcResidual = 0xf0b8 // YK_CRC_OK_RESIDUAL: CRC over (data||crc) of a valid frame
)

// Client-side poll deadlines. These bound our own waiting only; they don't
// affect the wire bytes or the resulting HMAC.
const (
	writeReadyTimeout = 2 * time.Second  // wait for the device to clear SLOT_WRITE_FLAG
	processTimeout    = 2 * time.Second  // wait for RESP_PENDING on a no-touch slot
	touchTimeout      = 20 * time.Second // additional wait when the slot requires a touch
	pollMin           = 1 * time.Millisecond
	pollMax           = 100 * time.Millisecond
)

var (
	hidInitOnce sync.Once
	hidInitErr  error
	// hidMu serializes device access. A YubiKey's OTP state machine (the
	// SLOT_WRITE_FLAG / RESP_PENDING flags + sequence counter) is global to the
	// physical key, so two concurrent in-process operations would interleave and
	// corrupt each other's frames.
	hidMu sync.Mutex
)

// hidEnsureInit initializes hidapi once for the process lifetime. hidapi is
// otherwise lazily initialized; we do it explicitly for concurrency safety and
// never call hid.Exit (the OS reclaims on exit), matching the old ykpers path.
func hidEnsureInit() error {
	hidInitOnce.Do(func() {
		if err := hid.Init(); err != nil {
			hidInitErr = fmt.Errorf("chalresp: hidapi init failed: %w", err)
		}
	})
	return hidInitErr
}

// hidList enumerates connected devices that expose the YubiKey OTP keyboard
// interface. Returns an empty slice (not an error) when none are present.
func hidList() ([]DeviceDescriptor, error) {
	if err := hidEnsureInit(); err != nil {
		return nil, err
	}
	var out []DeviceDescriptor
	collect := func(family string) hid.EnumFunc {
		return func(info *hid.DeviceInfo) error {
			// The OTP/chalresp interface is the HID keyboard collection. The hidraw
			// backend (Linux) populates UsagePage/Usage, so match the keyboard there.
			// The libusb backend (macOS/*BSD) does NOT fill usage (hidapi's
			// INVASIVE_GET_USAGE is off), leaving both 0 — there, fall back to USB
			// interface 0, which is the OTP interface on YubiKey/OnlyKey whenever it's
			// enabled (FIDO/CCID are later interfaces). This keeps us off the FIDO
			// collection on both backends.
			isKeyboard := info.UsagePage == usagePageKeyboard && info.Usage == usageKeyboard
			usageUnknown := info.UsagePage == 0 && info.Usage == 0
			if !isKeyboard && !(usageUnknown && info.InterfaceNbr == 0) {
				return nil
			}
			out = append(out, DeviceDescriptor{
				Family:  family,
				Serial:  info.SerialNbr,
				backend: backendHID,
				path:    info.Path,
			})
			return nil
		}
	}
	if err := hid.Enumerate(vidYubico, hid.ProductIDAny, collect("yubikey")); err != nil {
		return nil, fmt.Errorf("chalresp: enumerating YubiKey: %w", err)
	}
	if err := hid.Enumerate(vidOnlyKey, pidOnlyKey, collect("onlykey")); err != nil {
		return nil, fmt.Errorf("chalresp: enumerating OnlyKey: %w", err)
	}
	return out, nil
}

// hidIsSlot2Programmed reads the device status report and checks CONFIG2_VALID.
func hidIsSlot2Programmed(desc DeviceDescriptor) (bool, error) {
	hidMu.Lock()
	defer hidMu.Unlock()
	var programmed bool
	err := withDevice(desc, func(dev *hid.Device) error {
		st, err := readStatus(dev)
		if err != nil {
			return err
		}
		programmed = st[statusTouchOffset]&config2Valid != 0
		return nil
	})
	return programmed, err
}

// hidChallenge runs a slot-2 HMAC-SHA1 challenge-response. mayBlock=true waits
// for a physical touch on slots configured to require one.
func hidChallenge(desc DeviceDescriptor, challenge []byte, mayBlock bool) ([]byte, error) {
	hidMu.Lock()
	defer hidMu.Unlock()
	var resp []byte
	err := withDevice(desc, func(dev *hid.Device) error {
		frame := buildFrame(challenge, slotChalHMAC2)
		if err := sendFrame(dev, frame); err != nil {
			return err
		}
		r, err := readResponse(dev, mayBlock)
		if err != nil {
			return err
		}
		resp = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// withDevice opens the device (by its enumerated path, or the first available
// one if the descriptor carries none), runs fn, and closes it.
func withDevice(desc DeviceDescriptor, fn func(*hid.Device) error) error {
	if err := hidEnsureInit(); err != nil {
		return err
	}
	path := desc.path
	if path == "" {
		devs, err := hidList()
		if err != nil {
			return err
		}
		if len(devs) == 0 {
			return ErrNoDevice
		}
		path = devs[0].path
	}
	dev, err := hid.OpenPath(path)
	if err != nil {
		return fmt.Errorf("chalresp: opening device: %w", err)
	}
	defer dev.Close()
	return fn(dev)
}

// --- feature report I/O ------------------------------------------------------
// hidapi's report-ID convention: the buffer's first byte is the report ID
// (0x00 for the YubiKey's unnumbered reports), so an 8-byte device report is a
// 9-byte Go buffer with the 8 report bytes at [1:9].

func writeReport(dev *hid.Device, rep [featureRptSize]byte) error {
	buf := make([]byte, featureRptSize+1)
	copy(buf[1:], rep[:]) // buf[0] = 0x00 report ID
	if _, err := dev.SendFeatureReport(buf); err != nil {
		return fmt.Errorf("chalresp: send feature report: %w", err)
	}
	return nil
}

func readStatus(dev *hid.Device) ([featureRptSize]byte, error) {
	var st [featureRptSize]byte
	buf := make([]byte, featureRptSize+1)
	// buf[0] = 0x00 report ID to read
	if _, err := dev.GetFeatureReport(buf); err != nil {
		return st, fmt.Errorf("chalresp: get feature report: %w", err)
	}
	copy(st[:], buf[1:])
	return st, nil
}

// writeReset issues DUMMY_REPORT_WRITE to clear the device's read/write state.
func writeReset(dev *hid.Device) {
	var rep [featureRptSize]byte
	rep[featureRptSize-1] = dummyReport
	_ = writeReport(dev, rep) // best-effort
}

// --- frame construction ------------------------------------------------------

// padChallenge pads a challenge (<=64 bytes) to 64 using the yubikit rule: pad
// with 0x00, or 0x01 if the challenge ends in 0x00 (so a slot in HMAC_LT64
// variable-length mode recovers the exact length instead of stripping a real
// trailing zero). Correctness, not security.
func padChallenge(challenge []byte) [frameDataSize]byte {
	var p [frameDataSize]byte
	copy(p[:], challenge)
	if len(challenge) < frameDataSize {
		pad := byte(0x00)
		if len(challenge) > 0 && challenge[len(challenge)-1] == 0x00 {
			pad = 0x01
		}
		for i := len(challenge); i < frameDataSize; i++ {
			p[i] = pad
		}
	}
	return p
}

// buildFrame assembles the 70-byte frame: padded payload | slot | CRC16(payload)
// little-endian | 3 filler zeros.
func buildFrame(challenge []byte, slot byte) [frameSize]byte {
	payload := padChallenge(challenge)
	var frame [frameSize]byte
	copy(frame[:frameDataSize], payload[:])
	frame[frameDataSize] = slot
	crc := yubikeyCRC16(frame[:frameDataSize])
	frame[frameDataSize+1] = byte(crc & 0xff)
	frame[frameDataSize+2] = byte(crc >> 8)
	// frame[67..69] remain zero (filler)
	return frame
}

// yubikeyCRC16 is Yubico's CRC-16 (yubico-c ykcrc.c): init 0xFFFF, reflected,
// poly 0x8408; no final xor. A valid (data||crc) frame has residual 0xF0B8.
func yubikeyCRC16(buf []byte) uint16 {
	crc := uint16(0xffff)
	for _, b := range buf {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			j := crc & 1
			crc >>= 1
			if j == 1 {
				crc ^= 0x8408
			}
		}
	}
	return crc
}

func crcValid(buf []byte) bool { return yubikeyCRC16(buf) == crcResidual }

// --- write / read state machine ---------------------------------------------

// sendFrame writes the 70-byte frame as 10 seven-byte records. An all-zero
// record is skipped except the first (seq 0) and last (seq 9); the last always
// goes because it carries the slot command + CRC. Each write waits for the
// device to clear SLOT_WRITE_FLAG first.
func sendFrame(dev *hid.Device, frame [frameSize]byte) error {
	for seq := 0; seq < frameSize/recordDataSize; seq++ {
		var rec [recordDataSize]byte
		copy(rec[:], frame[seq*recordDataSize:(seq+1)*recordDataSize])
		if isZero(rec[:]) && seq > 0 && seq != (frameSize/recordDataSize)-1 {
			continue
		}
		if err := waitForWriteReady(dev); err != nil {
			return err
		}
		var rep [featureRptSize]byte
		copy(rep[:recordDataSize], rec[:])
		rep[featureRptSize-1] = byte(seq) | slotWriteFlag
		if err := writeReport(dev, rep); err != nil {
			return err
		}
	}
	return nil
}

// waitForWriteReady polls the status report until SLOT_WRITE_FLAG is clear,
// meaning the device has consumed the previous write record.
func waitForWriteReady(dev *hid.Device) error {
	deadline := time.Now().Add(writeReadyTimeout)
	sleep := pollMin
	for {
		st, err := readStatus(dev)
		if err != nil {
			return err
		}
		if st[featureRptSize-1]&slotWriteFlag == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("chalresp: timeout waiting for device to accept write")
		}
		time.Sleep(sleep)
		if sleep = sleep * 2; sleep > pollMax {
			sleep = pollMax
		}
	}
}

// readResponse waits for RESP_PENDING, then reads the response in 7-byte chunks
// until the terminator (RESP_PENDING set with sequence 0), verifies the CRC,
// and returns the 20-byte HMAC-SHA1. It always resets the device afterward.
func readResponse(dev *hid.Device, mayBlock bool) ([]byte, error) {
	first, err := waitForResponse(dev, mayBlock)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, frameSize)
	buf = append(buf, first[:recordDataSize]...)

	// Bounded by buffer growth (~9 chunks); the explicit counter is belt-and-
	// suspenders against a flooding device if the frame constants ever change.
	const maxReads = 16
	for reads := 0; len(buf)+recordDataSize <= frameSize; reads++ {
		if reads >= maxReads {
			writeReset(dev)
			wipe(buf)
			return nil, errors.New("chalresp: too many response reports")
		}
		rep, err := readStatus(dev)
		if err != nil {
			writeReset(dev)
			wipe(buf)
			return nil, err
		}
		flags := rep[featureRptSize-1]
		if flags&respPendingFlag == 0 {
			writeReset(dev)
			wipe(buf)
			return nil, errors.New("chalresp: response aborted by device")
		}
		if flags&sequenceMask == 0 {
			// Terminator. The response is 20-byte HMAC + 2-byte CRC.
			const respLen = hmacLen + 2
			if len(buf) < respLen || !crcValid(buf[:respLen]) {
				writeReset(dev)
				wipe(buf)
				return nil, errors.New("chalresp: response CRC check failed (slot empty or wrong config?)")
			}
			writeReset(dev)
			resp := append([]byte(nil), buf[:hmacLen]...)
			wipe(buf) // clear the intermediate secret accumulator
			return resp, nil
		}
		buf = append(buf, rep[:recordDataSize]...)
	}
	writeReset(dev)
	wipe(buf)
	return nil, errors.New("chalresp: response exceeded expected length")
}

// waitForResponse polls until RESP_PENDING is set, returning the report that
// carries the first response bytes. If the slot requires a touch
// (RESP_TIMEOUT_WAIT_FLAG) and mayBlock is false, it returns ErrTouchTimeout
// immediately; if mayBlock, it extends the deadline to wait for the touch.
func waitForResponse(dev *hid.Device, mayBlock bool) ([featureRptSize]byte, error) {
	var last [featureRptSize]byte
	deadline := time.Now().Add(processTimeout)
	extended := false
	sleep := pollMin
	for {
		st, err := readStatus(dev)
		if err != nil {
			return st, err
		}
		last = st
		flags := st[featureRptSize-1]
		if flags&respPendingFlag != 0 {
			return st, nil
		}
		if flags&respTimeoutWaitFlag != 0 {
			// Device is waiting for a physical touch.
			if !mayBlock {
				writeReset(dev)
				return st, ErrTouchTimeout
			}
			if !extended {
				extended = true
				deadline = time.Now().Add(touchTimeout)
			}
		}
		if time.Now().After(deadline) {
			writeReset(dev)
			if extended {
				return last, ErrTouchTimeout
			}
			return last, errors.New("chalresp: timeout waiting for response")
		}
		time.Sleep(sleep)
		if sleep = sleep * 2; sleep > pollMax {
			sleep = pollMax
		}
	}
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
