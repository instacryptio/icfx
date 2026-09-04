package crypto

import (
	"bytes"
	"strings"
	"testing"
)

const testFingerprint = "a1b2c3d4e5f6g7h8"

func TestGitSign_RoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	commit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n\n" +
		"Initial commit\n")

	var sigBuf bytes.Buffer
	if err := GitSign(bytes.NewReader(commit), &sigBuf, kp.SigningPrivateKey, kp.Fingerprint); err != nil {
		t.Fatalf("GitSign: %v", err)
	}

	armored := sigBuf.Bytes()
	if !strings.Contains(string(armored), "-----BEGIN ICFX GIT SIGNATURE-----") {
		t.Errorf("expected armored signature header, got:\n%s", armored)
	}
	if !strings.Contains(string(armored), "-----END ICFX GIT SIGNATURE-----") {
		t.Errorf("expected armored signature footer, got:\n%s", armored)
	}
	if !strings.Contains(string(armored), "Fingerprint: "+kp.Fingerprint) {
		t.Errorf("expected fingerprint header in output:\n%s", armored)
	}

	ok, err := GitVerify(bytes.NewReader(commit), armored, kp.SigningPublicKey)
	if err != nil {
		t.Fatalf("GitVerify: %v", err)
	}
	if !ok {
		t.Errorf("GitVerify returned false for valid signature")
	}
}

func TestGitSign_RequiresFingerprint(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	var buf bytes.Buffer
	err = GitSign(bytes.NewReader([]byte("data")), &buf, kp.SigningPrivateKey, "")
	if err == nil {
		t.Errorf("expected error for empty fingerprint")
	}
}

func TestParseGitSignature_ExtractsFingerprint(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	var sigBuf bytes.Buffer
	if err := GitSign(bytes.NewReader([]byte("commit data")), &sigBuf, kp.SigningPrivateKey, kp.Fingerprint); err != nil {
		t.Fatalf("GitSign: %v", err)
	}

	sig, fpr, err := ParseGitSignature(sigBuf.Bytes())
	if err != nil {
		t.Fatalf("ParseGitSignature: %v", err)
	}
	if fpr != kp.Fingerprint {
		t.Errorf("fingerprint = %q, want %q", fpr, kp.Fingerprint)
	}
	if len(sig) == 0 {
		t.Errorf("expected non-empty signature bytes")
	}
}

func TestParseGitSignature_LegacyNoHeader(t *testing.T) {
	// Build a legacy-format signature (no headers) using ArmorGitSignature with empty fingerprint.
	rawSig := []byte("dummy raw signature bytes that pretend to be ML-DSA-65")
	armored := ArmorGitSignature(rawSig, "")

	sig, fpr, err := ParseGitSignature(armored)
	if err != nil {
		t.Fatalf("ParseGitSignature on legacy format: %v", err)
	}
	if fpr != "" {
		t.Errorf("expected empty fingerprint for legacy format, got %q", fpr)
	}
	if !bytes.Equal(sig, rawSig) {
		t.Errorf("signature mismatch")
	}
}

func TestGitVerify_TamperedContent(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	original := []byte("hello world")
	tampered := []byte("hello WORLD")

	var sigBuf bytes.Buffer
	if err := GitSign(bytes.NewReader(original), &sigBuf, kp.SigningPrivateKey, kp.Fingerprint); err != nil {
		t.Fatalf("GitSign: %v", err)
	}

	ok, _ := GitVerify(bytes.NewReader(tampered), sigBuf.Bytes(), kp.SigningPublicKey)
	if ok {
		t.Errorf("GitVerify accepted tampered content")
	}
}

func TestGitVerify_WrongLabel(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Build an armored blob with the wrong label
	wrong := []byte("-----BEGIN ICFX LOCK-----\nAAAA\n-----END ICFX LOCK-----\n")

	_, err = GitVerify(bytes.NewReader([]byte("data")), wrong, kp.SigningPublicKey)
	if err == nil {
		t.Errorf("expected error for wrong armor label, got nil")
	}
}

func TestGitVerify_MalformedArmor(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cases := [][]byte{
		[]byte(""),
		[]byte("not armored at all"),
		[]byte("-----BEGIN ICFX GIT SIGNATURE-----\n"), // no end
		[]byte("-----BEGIN ICFX GIT SIGNATURE-----\n!!!notbase64!!!\n-----END ICFX GIT SIGNATURE-----\n"),
	}
	for i, c := range cases {
		_, err := GitVerify(bytes.NewReader([]byte("data")), c, kp.SigningPublicKey)
		if err == nil {
			t.Errorf("case %d: expected error for malformed armor, got nil", i)
		}
	}
}

func TestArmorParseGitSignature(t *testing.T) {
	original := []byte("raw signature bytes")
	armored := ArmorGitSignature(original, testFingerprint)
	got, fpr, err := ParseGitSignature(armored)
	if err != nil {
		t.Fatalf("ParseGitSignature: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("round-trip mismatch:\noriginal=%x\ngot=     %x", original, got)
	}
	if fpr != testFingerprint {
		t.Errorf("fingerprint round-trip: want %q, got %q", testFingerprint, fpr)
	}
}
