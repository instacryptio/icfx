package config

import "testing"

func TestValidateCloudBaseURL(t *testing.T) {
	ok := []string{
		"", // empty → use default
		"https://cloud.example.com",
		"https://cloud.example.com:8443",
		"http://localhost:8080",
		"http://127.0.0.1",
		"http://127.0.0.5:9000", // 127/8 loopback
		"http://[::1]:8080",
	}
	for _, u := range ok {
		if err := ValidateCloudBaseURL(u); err != nil {
			t.Errorf("ValidateCloudBaseURL(%q) = %v, want nil", u, err)
		}
	}

	bad := []string{
		"http://cloud.example.com",  // plaintext to remote host
		"http://198.51.100.10:8080", // plaintext to remote IP
		"ftp://localhost",           // wrong scheme
		"wss://cloud.example.com",   // wrong scheme
	}
	for _, u := range bad {
		if err := ValidateCloudBaseURL(u); err == nil {
			t.Errorf("ValidateCloudBaseURL(%q) = nil, want error", u)
		}
	}
}
