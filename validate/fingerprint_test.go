package validate

import "testing"

func TestValidateFingerprint(t *testing.T) {
	tests := []struct {
		name    string
		fp      string
		wantErr bool
	}{
		{"valid", "abcdef0123456789abcdef0123456789", false},
		{"valid uppercase", "ABCDEF0123456789ABCDEF0123456789", false},
		{"empty", "", true},
		{"too short (16)", "abcdef0123456789", true},
		{"too long", "abcdef0123456789abcdef0123456789a", true},
		{"non-hex", "ghijklmnopqrstuvghijklmnopqrstuv", true},
		{"mixed valid/invalid", "abcdef0123456789abcdef01234567zz", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFingerprint(tt.fp)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFingerprint(%q) error = %v, wantErr %v", tt.fp, err, tt.wantErr)
			}
		})
	}
}
