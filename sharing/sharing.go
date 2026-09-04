// Package sharing is the transport layer for encrypted file shares: it
// uploads pre-encrypted .icfx payloads and downloads ciphertext for the
// caller to decrypt. It performs no cryptography itself — senders encrypt
// with the icfx encrypt flows before upload (the server and object store
// only ever see ciphertext), and receivers decrypt with their
// container-aware paths (signature verification needs the caller's contact
// store). Both directions stream, so share sizes are bounded by the plan
// tier, not by RAM.
package sharing

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/recipient"
)

// Recipient identifies who a share is for. Both fields come from the local
// contact record: the Lock is what the payload must be encrypted to, the
// Fingerprint addresses the share (it must match a fingerprint the
// recipient has published in the directory — it is the download
// authorization).
type Recipient struct {
	Lock        string
	Fingerprint string
	// Alias is the contact's local alias, used only to compose user-facing
	// warnings (e.g. "not published"); the transport ignores it.
	Alias string
}

type SendOptions struct {
	// TTL 0 = the share never expires; it holds one of the tier's active
	// share slots until the sender deletes it.
	TTL       time.Duration
	SingleUse bool
	// NoNotify suppresses the recipient notification email. The share still
	// appears in the recipient's inbox/notifications.
	NoNotify bool
	// ToSelf shares to the account's own devices (device-to-device transfer
	// of a self-encrypted file). The Recipient must be zero — no fingerprint
	// is sent (the server never learns the identity), no email exists, and
	// no directory publication is required.
	ToSelf bool
}

type SendResult struct {
	ShareID         string
	CiphertextBytes int64
	// Warnings are ready-to-render advisory messages composed in icfx (so every
	// client renders them identically) — e.g. a recipient who isn't published to
	// the directory yet. The share still succeeds; callers just print these.
	Warnings []string
}

// SendEncrypted uploads an existing icfx ciphertext file (already encrypted
// to the recipient's lock — the output of an icfx encrypt) as a share:
// create (slot + size checked server-side) → upload → finalize (server
// verifies the stored byte count and, unless NoNotify, emails the
// recipient). The share is named after the file itself.
//
// The container header is ALWAYS stripped before upload: the stored object
// must not reveal filename or sender fingerprint to the storage operator.
// v2 containers keep their encrypted inner metadata copy; a stripped v1
// simply loses them (receive naming comes from the share record).
func SendEncrypted(ctx context.Context, c *cloud.Client, to []Recipient, ciphertextPath string, opts SendOptions) (SendResult, error) {
	return SendEncryptedProgress(ctx, c, to, ciphertextPath, opts, nil)
}

// SendEncryptedProgress is SendEncrypted with an optional upload progress
// callback, invoked as bytes are uploaded with the running sent count and the
// exact total (known before the upload starts, so it's determinate from byte 0).
// onProgress may be nil.
func SendEncryptedProgress(ctx context.Context, c *cloud.Client, to []Recipient, ciphertextPath string, opts SendOptions, onProgress func(sent, total int64)) (SendResult, error) {
	// One uploaded blob authorized for N contact fingerprints, plus (opts.ToSelf)
	// the sender's own devices. The blob is already encrypted to every recipient
	// upstream — the transport only addresses it. Self is signalled via ToSelf,
	// not a fingerprint (the server never learns the identity).
	fps := make([]string, 0, len(to))
	for _, r := range to {
		if r.Fingerprint != "" {
			fps = append(fps, r.Fingerprint)
		}
	}
	if len(fps) == 0 && !opts.ToSelf {
		return SendResult{}, fmt.Errorf("a share needs at least one recipient")
	}
	f, err := os.Open(ciphertextPath)
	if err != nil {
		return SendResult{}, fmt.Errorf("open ciphertext: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return SendResult{}, fmt.Errorf("stat ciphertext: %w", err)
	}

	// Streaming header strip: replace the fixed prefix with a zero-length
	// header marker and skip the plaintext metadata block; payload and
	// signature bytes stream through untouched (the signature covers only
	// the payload, so it stays valid).
	head := make([]byte, format.HeaderPrefixLen)
	if _, err := io.ReadFull(f, head); err != nil {
		return SendResult{}, fmt.Errorf("reading container header: %w", err)
	}
	_, metaLen, err := format.ParseHeaderPrefix(head)
	if err != nil {
		return SendResult{}, fmt.Errorf("preparing private container: %w", err)
	}
	if _, err := f.Seek(int64(format.HeaderPrefixLen+metaLen), io.SeekStart); err != nil {
		return SendResult{}, fmt.Errorf("skipping header metadata: %w", err)
	}
	format.ZeroMetaLen(head) // header metadata length → 0 (private)
	size := st.Size() - int64(metaLen)
	body := io.MultiReader(bytes.NewReader(head), f)

	created, err := c.CreateShare(ctx, cloud.ShareCreateInput{
		RecipientFingerprints: fps,
		ToSelf:                opts.ToSelf,
		TTL:                   opts.TTL,
		SingleUse:             opts.SingleUse,
		FileName:              filepath.Base(ciphertextPath),
		FileSize:              size,
	})
	if err != nil {
		return SendResult{}, err
	}
	var upload io.Reader = body
	if onProgress != nil {
		upload = &progressReader{r: body, total: size, cb: onProgress}
	}
	if err := c.UploadStreamToPresignedURL(ctx, created.UploadURL, upload, size); err != nil {
		return SendResult{}, err
	}
	if _, err := c.FinalizeShare(ctx, created.ShareID, !opts.NoNotify); err != nil {
		return SendResult{}, err
	}
	// Compose advisory warnings for recipients the server reports as not
	// currently published (mapping each fingerprint back to its alias). Done
	// here in icfx so every client renders the same message.
	var warnings []string
	if len(created.UnreachableFingerprints) > 0 {
		aliasByFp := make(map[string]string, len(to))
		for _, r := range to {
			aliasByFp[strings.ToLower(r.Fingerprint)] = r.Alias
		}
		for _, fp := range created.UnreachableFingerprints {
			alias := aliasByFp[strings.ToLower(fp)]
			if alias == "" {
				alias = fp
			}
			warnings = append(warnings, recipient.ShareWarnUnpublished(alias))
		}
	}

	return SendResult{
		ShareID:         created.ShareID,
		CiphertextBytes: size,
		Warnings:        warnings,
	}, nil
}

// DownloadCiphertext streams a share's ciphertext into w after the server
// authorizes the caller as the addressed recipient. The caller decrypts —
// typically by detecting the icfx container format and running the full
// parse + signature-verify + decrypt path.
func DownloadCiphertext(ctx context.Context, c *cloud.Client, shareID string, w io.Writer) (cloud.ShareDownload, error) {
	return DownloadCiphertextProgress(ctx, c, shareID, w, nil)
}

// DownloadCiphertextProgress is DownloadCiphertext with an optional progress
// callback, invoked as bytes arrive with the running downloaded count and the
// server-declared total (0 when unknown). The callback fires once per read
// chunk — callers that surface it to a UI should throttle. onProgress may be nil.
func DownloadCiphertextProgress(ctx context.Context, c *cloud.Client, shareID string, w io.Writer, onProgress func(downloaded, total int64)) (cloud.ShareDownload, error) {
	dl, err := c.DownloadShare(ctx, shareID)
	if err != nil {
		return cloud.ShareDownload{}, err
	}
	body, err := c.FetchPresignedURL(ctx, dl.URL)
	if err != nil {
		return cloud.ShareDownload{}, err
	}
	defer body.Close()
	var src io.Reader = body
	if onProgress != nil {
		src = &progressReader{r: body, total: dl.FileSize, cb: onProgress}
	}
	if _, err := io.Copy(w, src); err != nil {
		return cloud.ShareDownload{}, fmt.Errorf("downloading share: %w", err)
	}
	return dl, nil
}

// DownloadRaw streams a share's RAW encrypted .icfx into w after the server
// authorizes the caller as the SENDER of the share. No decryption happens — the
// caller receives the ciphertext blob exactly as stored (a valid icfx container
// with a stripped header). Use this to retrieve a blob you uploaded; recipients
// use DownloadCiphertext (which they then decrypt).
func DownloadRaw(ctx context.Context, c *cloud.Client, shareID string, w io.Writer) (cloud.ShareDownload, error) {
	return DownloadRawProgress(ctx, c, shareID, w, nil)
}

// DownloadRawProgress is DownloadRaw with an optional progress callback (running
// downloaded count + server-declared total; fires once per read chunk, so a UI
// should throttle). onProgress may be nil.
func DownloadRawProgress(ctx context.Context, c *cloud.Client, shareID string, w io.Writer, onProgress func(downloaded, total int64)) (cloud.ShareDownload, error) {
	dl, err := c.DownloadShareRaw(ctx, shareID)
	if err != nil {
		return cloud.ShareDownload{}, err
	}
	body, err := c.FetchPresignedURL(ctx, dl.URL)
	if err != nil {
		return cloud.ShareDownload{}, err
	}
	defer body.Close()
	var src io.Reader = body
	if onProgress != nil {
		src = &progressReader{r: body, total: dl.FileSize, cb: onProgress}
	}
	if _, err := io.Copy(w, src); err != nil {
		return cloud.ShareDownload{}, fmt.Errorf("downloading share: %w", err)
	}
	return dl, nil
}

// progressReader reports cumulative bytes read to a callback.
type progressReader struct {
	r     io.Reader
	total int64
	n     int64
	cb    func(downloaded, total int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.n += int64(n)
		p.cb(p.n, p.total)
	}
	return n, err
}

// ReceiveName derives a safe local file name from the sender-declared share
// name: path components are stripped (a hostile name can't traverse out of
// the destination directory) and the ciphertext extension is removed.
func ReceiveName(declared, shareID string) string {
	name := filepath.Base(strings.TrimSpace(declared))
	name = strings.TrimSuffix(name, ".icfx")
	switch name {
	case "", ".", "..", string(filepath.Separator):
		return "share-" + shareID
	}
	return name
}

// ShareIDFromLink extracts the share id from a legacy share link
// (…/v1/share/<uuid>) or returns the input unchanged if it is already a
// bare id.
func ShareIDFromLink(s string) string {
	s = strings.TrimSpace(strings.TrimRight(s, "/"))
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}
