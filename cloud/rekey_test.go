package cloud

// Unit tests for the self-lock re-key core (rekey.go). They stand up an
// in-memory blob/ops server via httptest so the reseal logic (resealBlob /
// resealContacts / RekeySelfLock) is exercised end-to-end without a real
// ic-cloud server. A real-crypto SelfCrypter (rekeyCrypter) lets the tests
// assert that resealed blobs decrypt under the NEW key and fail under the OLD.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/groups"
)

// rekeyCrypter is a real-crypto SelfCrypter: seal to pub, open with priv.
// Sealing with keypair A then Decrypt-ing with keypair B yields an
// age.NoIdentityMatchError — exactly the mismatch isRecipientMismatch keys on.
type rekeyCrypter struct{ pub, priv string }

func (c rekeyCrypter) EncryptToSelf(p []byte) ([]byte, error) {
	return crypto.Encrypt(p, []string{c.pub})
}
func (c rekeyCrypter) Decrypt(ct []byte) ([]byte, error) { return crypto.Decrypt(ct, c.priv) }

func newRekeyCrypter(t *testing.T) rekeyCrypter {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return rekeyCrypter{pub: kp.EncryptionRecipient, priv: kp.EncryptionIdentity}
}

// mapResourceIO is a map-backed ResourceIO — avoids configResourceIO's global
// contacts/config reads so a rekey test controls the exact local plaintext.
type mapResourceIO struct{ data map[string][]byte }

func (m mapResourceIO) Load(name string) ([]byte, error)  { return m.data[name], nil }
func (m mapResourceIO) Apply(name string, d []byte) error { m.data[name] = d; return nil }

// --- in-memory blob/ops server ------------------------------------------------

type fakeBlob struct {
	ct      []byte
	version int64
}

type blobServer struct {
	blobs          map[string]*fakeBlob
	opsMaxSeq      map[string]int64  // resource -> op-log high-water mark
	compactCalls   map[string][]byte // resource -> last snapshot ciphertext seen
	lastThroughSeq map[string]int64  // resource -> last compact through_seq
	putConflicts   map[string]int    // name -> number of 409s to force before success
	srv            *httptest.Server
}

func newBlobServer(t *testing.T) *blobServer {
	t.Helper()
	bs := &blobServer{
		blobs:          map[string]*fakeBlob{},
		opsMaxSeq:      map[string]int64{},
		compactCalls:   map[string][]byte{},
		lastThroughSeq: map[string]int64{},
		putConflicts:   map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sync/state", bs.handleState)
	mux.HandleFunc("/v1/blob/", bs.handleBlob)
	mux.HandleFunc("/v1/ops/", bs.handleOps)
	bs.srv = httptest.NewServer(mux)
	t.Cleanup(bs.srv.Close)
	return bs
}

func (bs *blobServer) handleState(w http.ResponseWriter, _ *http.Request) {
	out := ServerSyncState{}
	for name, b := range bs.blobs {
		out.Blobs = append(out.Blobs, ServerBlobMeta{Name: name, Version: b.version})
	}
	for res, seq := range bs.opsMaxSeq {
		out.Ops = append(out.Ops, ServerOpsMeta{Resource: res, MaxSeq: seq})
	}
	bsJSON(w, http.StatusOK, out)
}

func (bs *blobServer) handleBlob(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/v1/blob/")
	switch r.Method {
	case http.MethodGet:
		b, ok := bs.blobs[name]
		if !ok {
			bsErr(w, http.StatusNotFound, "not_found", 0)
			return
		}
		bsJSON(w, http.StatusOK, map[string]any{
			"version":        b.version,
			"ciphertext_b64": base64.StdEncoding.EncodeToString(b.ct),
		})
	case http.MethodPut:
		var body struct {
			Ciphertext  string `json:"ciphertext_b64"`
			PrevVersion int64  `json:"prev_version"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if bs.putConflicts[name] > 0 {
			bs.putConflicts[name]--
			cur := int64(0)
			if b, ok := bs.blobs[name]; ok {
				cur = b.version
			}
			bsErr(w, http.StatusConflict, "conflict", cur)
			return
		}
		ct, _ := base64.StdEncoding.DecodeString(body.Ciphertext)
		ver := int64(1)
		if cur, ok := bs.blobs[name]; ok {
			ver = cur.version + 1
		}
		bs.blobs[name] = &fakeBlob{ct: ct, version: ver}
		bsJSON(w, http.StatusOK, PutBlobResult{Version: ver})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (bs *blobServer) handleOps(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/ops/")
	if !strings.HasSuffix(path, "/compact") {
		bsErr(w, http.StatusNotFound, "not_found", 0)
		return
	}
	res := strings.TrimSuffix(path, "/compact")
	var body struct {
		Snapshot    string `json:"snapshot_b64"`
		ThroughSeq  int64  `json:"through_seq"`
		PrevVersion int64  `json:"prev_version"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	snap, _ := base64.StdEncoding.DecodeString(body.Snapshot)
	bs.compactCalls[res] = snap
	bs.lastThroughSeq[res] = body.ThroughSeq
	ver := int64(1)
	if cur, ok := bs.blobs[res]; ok {
		ver = cur.version + 1
	}
	bs.blobs[res] = &fakeBlob{ct: snap, version: ver}
	bs.opsMaxSeq[res] = 0 // ops truncated through throughSeq
	bsJSON(w, http.StatusOK, map[string]any{"version": ver})
}

// seedSealed pre-loads a cloud blob sealed under u (mimics the OLD default's copy).
func (bs *blobServer) seedSealed(t *testing.T, u SelfCrypter, name string, plaintext []byte) {
	t.Helper()
	ct, err := u.EncryptToSelf(plaintext)
	if err != nil {
		t.Fatalf("seed seal %s: %v", name, err)
	}
	ver := int64(1)
	if cur, ok := bs.blobs[name]; ok {
		ver = cur.version + 1
	}
	bs.blobs[name] = &fakeBlob{ct: ct, version: ver}
}

func bsJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func bsErr(w http.ResponseWriter, status int, code string, currentVersion int64) {
	bsJSON(w, status, map[string]any{"code": code, "current_version": currentVersion})
}

func newRekeyTestClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := New(url)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.SetTokens(&Tokens{
		AccessToken:      "test-token",
		ExpiresAt:        time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(24 * time.Hour),
	})
	return c
}

// --- tests --------------------------------------------------------------------

func TestIsRecipientMismatch(t *testing.T) {
	a := newRekeyCrypter(t)
	b := newRekeyCrypter(t)
	ct, err := a.EncryptToSelf([]byte("secret"))
	if err != nil {
		t.Fatalf("EncryptToSelf: %v", err)
	}
	if _, err := b.Decrypt(ct); err == nil {
		t.Fatal("expected decrypt under the wrong key to fail")
	} else if !isRecipientMismatch(err) {
		t.Errorf("isRecipientMismatch(cross-key decrypt err) = false, want true (err=%v)", err)
	}
	if isRecipientMismatch(errors.New("some other failure")) {
		t.Error("isRecipientMismatch(generic err) = true, want false")
	}
	if !isRecipientMismatch(age.ErrIncorrectIdentity) {
		t.Error("isRecipientMismatch(age.ErrIncorrectIdentity) = false, want true")
	}
}

func TestResealBlobConflictRetry(t *testing.T) {
	bs := newBlobServer(t)
	c := newRekeyTestClient(t, bs.srv.URL)
	u := newRekeyCrypter(t)

	// Existing cloud blob at version 5; force ONE 409 on the next PUT so
	// resealBlob must re-read the current version (5) and retry → 6.
	bs.blobs["settings"] = &fakeBlob{ct: []byte("stale"), version: 5}
	bs.putConflicts["settings"] = 1

	versions := map[string]int64{}
	if err := resealBlob(context.Background(), c, u, "settings", []byte("new-plaintext"), 0, versions); err != nil {
		t.Fatalf("resealBlob: %v", err)
	}
	if versions["settings"] != 6 {
		t.Errorf("versions[settings] = %d, want 6 (5 + retry)", versions["settings"])
	}
	pt, err := u.Decrypt(bs.blobs["settings"].ct)
	if err != nil {
		t.Fatalf("decrypt resealed blob: %v", err)
	}
	if string(pt) != "new-plaintext" {
		t.Errorf("resealed plaintext = %q, want new-plaintext", pt)
	}
}

func TestRekeySelfLockReencryptsBlobs(t *testing.T) {
	config.SetDataPath(t.TempDir()) // resealContacts → RemoveContactsShadow stays in temp
	bs := newBlobServer(t)
	c := newRekeyTestClient(t, bs.srv.URL)
	oldU := newRekeyCrypter(t)
	newU := newRekeyCrypter(t)

	// Cloud copies sealed under the OLD default's lock.
	bs.seedSealed(t, oldU, "settings", []byte(`{"k":"v"}`))
	gstore := groups.NewStoreWithPath(filepath.Join(t.TempDir(), "groups.json"))
	// Real local group data — the reseal guard refuses to overwrite a cloud blob
	// from an EMPTY local source, so an authoritative device must actually hold it.
	if _, err := gstore.Add("Team", []string{"c1", "c2"}); err != nil {
		t.Fatalf("groups Add: %v", err)
	}
	gbytes, err := gstore.SyncBytes()
	if err != nil {
		t.Fatalf("groups SyncBytes: %v", err)
	}
	bs.seedSealed(t, oldU, "groups", gbytes)

	io := mapResourceIO{data: map[string][]byte{
		"settings": []byte(`{"k":"v"}`),
		"contacts": []byte("[]"),
	}}

	// SettingsDigest set → this device has synced settings before, so settings is
	// authoritative and re-keyed (a never-synced device skips it; see
	// TestRekeySelfLockSkipsSettingsWhenNeverSynced).
	st := SyncPositions{SettingsDigest: "seeded"}
	if err := RekeySelfLock(context.Background(), c, newU, io, gstore, nil, &st); err != nil {
		t.Fatalf("RekeySelfLock: %v", err)
	}

	// settings + groups now decrypt under newU and FAIL under oldU.
	for _, name := range []string{"settings", "groups"} {
		b := bs.blobs[name]
		if b == nil {
			t.Fatalf("%s blob missing after rekey", name)
		}
		if _, err := newU.Decrypt(b.ct); err != nil {
			t.Errorf("%s: decrypt under newU failed after rekey: %v", name, err)
		}
		if _, err := oldU.Decrypt(b.ct); err == nil {
			t.Errorf("%s: decrypt under oldU succeeded after rekey — blob not re-sealed", name)
		}
	}
}

func TestResealContactsRecompacts(t *testing.T) {
	config.SetDataPath(t.TempDir()) // RemoveContactsShadow stays in temp
	bs := newBlobServer(t)
	c := newRekeyTestClient(t, bs.srv.URL)
	newU := newRekeyCrypter(t)

	// Server holds a contacts snapshot at v3 and ops up to seq 7.
	bs.blobs["contacts"] = &fakeBlob{ct: []byte("old-cipher"), version: 3}
	bs.opsMaxSeq["contacts"] = 7

	// Authoritative local contacts — the reseal guard refuses an empty overwrite.
	const localContacts = `[{"id":"c1","name":"Ada"}]`
	io := mapResourceIO{data: map[string][]byte{"contacts": []byte(localContacts)}}
	state, err := c.FetchSyncState(context.Background())
	if err != nil {
		t.Fatalf("FetchSyncState: %v", err)
	}

	var st SyncPositions
	if err := resealContacts(context.Background(), c, newU, io, state, &st); err != nil {
		t.Fatalf("resealContacts: %v", err)
	}
	if bs.lastThroughSeq["contacts"] != 7 {
		t.Errorf("compact through_seq = %d, want 7 (server MaxSeq)", bs.lastThroughSeq["contacts"])
	}
	if st.Contacts.Seq != 7 {
		t.Errorf("st.Contacts.Seq = %d, want 7", st.Contacts.Seq)
	}
	if st.Contacts.SnapshotVersion != 4 {
		t.Errorf("st.Contacts.SnapshotVersion = %d, want 4 (3+1)", st.Contacts.SnapshotVersion)
	}
	pt, err := newU.Decrypt(bs.compactCalls["contacts"])
	if err != nil {
		t.Fatalf("decrypt recompacted snapshot: %v", err)
	}
	if string(pt) != localContacts {
		t.Errorf("recompacted snapshot plaintext = %q, want %q", pt, localContacts)
	}
}

// TestRekeySelfLockSkipsSettingsWhenNeverSynced (F1): a device that has never
// synced settings (empty SettingsDigest) must NOT re-key the cloud settings blob
// — otherwise a fresh create/import would clobber another device's settings with
// its own defaults. Settings has no empty state, so this digest gate is its only
// authoritative-copy signal.
func TestRekeySelfLockSkipsSettingsWhenNeverSynced(t *testing.T) {
	config.SetDataPath(t.TempDir())
	bs := newBlobServer(t)
	c := newRekeyTestClient(t, bs.srv.URL)
	oldU := newRekeyCrypter(t)
	newU := newRekeyCrypter(t)
	bs.seedSealed(t, oldU, "settings", []byte(`{"default_format":"age"}`))

	io := mapResourceIO{data: map[string][]byte{
		"settings": []byte(`{"default_format":"age"}`),
		"contacts": []byte("[]"),
	}}
	var st SyncPositions // SettingsDigest == "" → never synced settings here
	if err := RekeySelfLock(context.Background(), c, newU, io, nil, nil, &st); err != nil {
		t.Fatalf("RekeySelfLock: %v", err)
	}
	b := bs.blobs["settings"]
	if b == nil {
		t.Fatal("settings blob vanished")
	}
	if _, err := oldU.Decrypt(b.ct); err != nil {
		t.Error("settings no longer decrypts under the OLD key — it was re-keyed despite empty SettingsDigest")
	}
	if _, err := newU.Decrypt(b.ct); err == nil {
		t.Error("settings decrypts under the NEW key — RekeySelfLock resealed it on a never-synced device")
	}
}

// TestResealBlobGuardsEmptyOnConflictReveal (F2): if the initial version is 0
// (blob looked absent) but a conflict reveals a populated blob another device
// created, the empty-source guard must still fire on the retry — not overwrite it.
func TestResealBlobGuardsEmptyOnConflictReveal(t *testing.T) {
	bs := newBlobServer(t)
	c := newRekeyTestClient(t, bs.srv.URL)
	u := newRekeyCrypter(t)

	bs.blobs["groups"] = &fakeBlob{ct: []byte("real-groups-cipher"), version: 3}
	bs.putConflicts["groups"] = 1 // first PUT 409s → resealBlob re-reads v3, re-checks the guard
	emptyGroups := []byte(`{"version":1,"groups":[]}`)

	// curVersion 0 = what a stale FetchSyncState reported before the concurrent create.
	err := resealBlob(context.Background(), c, u, "groups", emptyGroups, 0, map[string]int64{})
	if !errors.Is(err, ErrNoLocalToRecover) {
		t.Fatalf("resealBlob: err = %v, want ErrNoLocalToRecover after the conflict revealed a populated blob", err)
	}
	if b := bs.blobs["groups"]; b == nil || b.version != 3 || string(b.ct) != "real-groups-cipher" {
		t.Errorf("groups blob was overwritten (%+v) — guard didn't re-fire on the retry", b)
	}
}

// TestResealGuardsEmptyLocal asserts the data-loss guard: a device with NO local
// data must never overwrite a populated cloud blob (single-blob or contacts).
func TestResealGuardsEmptyLocal(t *testing.T) {
	config.SetDataPath(t.TempDir())
	bs := newBlobServer(t)
	c := newRekeyTestClient(t, bs.srv.URL)
	u := newRekeyCrypter(t)

	// Single blob (groups) present in the cloud, empty local source.
	empty, err := groups.NewStoreWithPath(filepath.Join(t.TempDir(), "g.json")).SyncBytes()
	if err != nil {
		t.Fatalf("empty groups SyncBytes: %v", err)
	}
	versions := map[string]int64{}
	if err := resealBlob(context.Background(), c, u, "groups", empty, 2, versions); !errors.Is(err, ErrNoLocalToRecover) {
		t.Fatalf("resealBlob empty groups: err = %v, want ErrNoLocalToRecover", err)
	}
	if _, wrote := bs.blobs["groups"]; wrote {
		t.Errorf("groups blob was written despite empty local — cloud overwrite not prevented")
	}

	// Contacts present in the cloud (snapshot + ops), empty local list.
	bs.blobs["contacts"] = &fakeBlob{ct: []byte("old-cipher"), version: 3}
	bs.opsMaxSeq["contacts"] = 7
	state, err := c.FetchSyncState(context.Background())
	if err != nil {
		t.Fatalf("FetchSyncState: %v", err)
	}
	io := mapResourceIO{data: map[string][]byte{"contacts": []byte("[]")}}
	var st SyncPositions
	if err := resealContacts(context.Background(), c, u, io, state, &st); !errors.Is(err, ErrNoLocalToRecover) {
		t.Fatalf("resealContacts empty local: err = %v, want ErrNoLocalToRecover", err)
	}
	if _, compacted := bs.compactCalls["contacts"]; compacted {
		t.Errorf("contacts op-log was compacted/truncated despite empty local — data loss not prevented")
	}
}

func TestRekeySelfLockMinimal(t *testing.T) {
	bs := newBlobServer(t)
	c := newRekeyTestClient(t, bs.srv.URL)
	newU := newRekeyCrypter(t)

	var st SyncPositions
	if err := RekeySelfLock(context.Background(), c, newU, nil, nil, nil, &st); err != nil {
		t.Fatalf("RekeySelfLock (minimal): %v", err)
	}
	if len(bs.blobs) != 0 {
		t.Errorf("expected no blobs written with nil io/gstore/nstore, got %d", len(bs.blobs))
	}
}
