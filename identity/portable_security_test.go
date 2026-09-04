package identity

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/keystore"
)

// makeBundle encrypts a portableBundle with the given identity name under pass,
// producing bytes ImportBytes can consume. White-box: portableBundle is
// unexported, so this lives in package identity.
func makeBundle(t *testing.T, name string, pass []byte) []byte {
	t.Helper()
	pb := portableBundle{
		EncryptionIdentity: "AGE-SECRET-KEY-PQ-1TESTONLY",
		SigningPrivateKey:  base64.StdEncoding.EncodeToString([]byte("signing-key-bytes")),
		Info:               Identity{Name: name, Email: "x@example.com"},
	}
	raw, err := json.Marshal(pb)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	enc, err := crypto.EncryptWithPassphraseBytes(raw, pass)
	if err != nil {
		t.Fatalf("encrypt bundle: %v", err)
	}
	return enc
}

// H1 regression: ImportBytes must validate the (attacker-controlled) identity
// name at the library boundary, since it becomes a filesystem path component.
func TestImportBytes_RejectsPathTraversalName(t *testing.T) {
	pass := []byte("correcthorsebatterystaple")
	for _, name := range []string{"../../evil", "a/b", `a\b`, "..", "/abs/evil"} {
		bundle := makeBundle(t, name, pass)
		ks := keystore.NewFileStoreWithDir(t.TempDir())
		if _, err := ImportBytes(bundle, pass, ks, nil); err == nil {
			t.Fatalf("ImportBytes accepted a malicious identity name %q; want rejection", name)
		}
	}
}

// M1 regression: ImportBytes must refuse to overwrite an existing identity's
// keys rather than silently clobbering them.
func TestImportBytes_RefusesOverwrite(t *testing.T) {
	pass := []byte("correcthorsebatterystaple")
	ks := keystore.NewFileStoreWithDir(t.TempDir())
	if err := ks.StoreEncryptionIdentity("alice", "AGE-SECRET-KEY-PQ-1EXISTING"); err != nil {
		t.Fatalf("seed enc: %v", err)
	}
	if err := ks.StoreSigningKey("alice", []byte("existing-sign")); err != nil {
		t.Fatalf("seed sign: %v", err)
	}
	bundle := makeBundle(t, "alice", pass)
	if _, err := ImportBytes(bundle, pass, ks, nil); err == nil {
		t.Fatal("ImportBytes overwrote an existing identity; want refusal")
	}
}
