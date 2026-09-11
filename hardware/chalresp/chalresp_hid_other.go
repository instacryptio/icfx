//go:build !darwin && !android && !ios && !nohw

package chalresp

// hidConfigureOpen is a no-op on the non-darwin HID backends. Linux (hidraw) and
// Windows (hid.dll) don't have hidapi's macOS seize-on-open behavior, and go-hid's
// SetOpenExclusive is a darwin-only symbol, so there's nothing to configure here.
func hidConfigureOpen() {}
