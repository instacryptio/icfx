package cloud

import (
	"context"
	"strings"
	"testing"
)

func TestRunSyncGuards(t *testing.T) {
	// No session store wired → clear error, no network.
	c, _ := New("http://localhost:0")
	if _, err := c.RunSync(context.Background(), nil, SyncOptions{}); err == nil ||
		!strings.Contains(err.Error(), "SessionStore") {
		t.Fatalf("want SessionStore guard, got %v", err)
	}

	// Store but no account email → clear error.
	c.SetSessionStore(DefaultSessionStore(t.TempDir(), false, func() (string, error) { return "p", nil }, nil))
	if _, err := c.RunSync(context.Background(), nil, SyncOptions{}); err == nil ||
		!strings.Contains(err.Error(), "account") {
		t.Fatalf("want account guard, got %v", err)
	}
}

func TestLocalSourceHasData(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		local    []byte
		want     bool
	}{
		{"contacts empty", "contacts", []byte("[]"), false},
		{"contacts one", "contacts", []byte(`[{"id":"c1","name":"Ada"}]`), true},
		{"groups empty", "groups", []byte(`{"version":1,"groups":[]}`), false},
		{"groups one", "groups", []byte(`{"version":1,"groups":[{"id":"g1"}]}`), true},
		{"groups tombstone only", "groups", []byte(`{"version":1,"groups":[],"deleted":["g9"]}`), true},
		{"notifications empty", "notifications", []byte(`{"items":[]}`), false},
		{"notifications one", "notifications", []byte(`{"items":[{"id":"n1"}]}`), true},
		{"notifications dismissed only", "notifications", []byte(`{"items":[],"dismissed":["n9"]}`), true},
		{"settings always resealable", "settings", []byte(`{}`), true},
		{"unparseable is data", "contacts", []byte("not-json"), true},
		{"unknown resource is data", "mystery", []byte("[]"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := localSourceHasData(tc.resource, tc.local); got != tc.want {
				t.Errorf("localSourceHasData(%q, %s) = %v, want %v", tc.resource, tc.local, got, tc.want)
			}
		})
	}
}

func TestCanRecoverSettingsGate(t *testing.T) {
	// Settings recoverability keys only on SettingsDigest (no host/io needed).
	if canRecoverLocally("settings", nil, nil, &SyncPositions{}) {
		t.Error("settings with empty digest must NOT be recoverable (fresh device → info line, not a reseal prompt)")
	}
	if canRecoverLocally("settings", nil, nil, nil) {
		t.Error("settings with nil positions must NOT be recoverable")
	}
	if !canRecoverLocally("settings", nil, nil, &SyncPositions{SettingsDigest: "deadbeef"}) {
		t.Error("settings with a synced digest MUST be recoverable (authoritative device)")
	}
}

func TestFillMessage(t *testing.T) {
	cases := []struct {
		o          SyncOutcome
		wantLevel  string
		wantSubstr string
	}{
		{SyncOutcome{Resource: "contacts", Action: SyncPushedNew, Version: 1}, SyncLevelOK, "pushed (new, v1)"},
		{SyncOutcome{Resource: "settings", Action: SyncUpToDate, Version: 4}, SyncLevelInfo, "up to date (v4)"},
		{SyncOutcome{Resource: "identities", Action: SyncPulled, Version: 3}, SyncLevelOK, "pulled (v3)"},
		{SyncOutcome{Resource: "contacts", Action: SyncPulled, Version: 3, CloudWasNewer: true}, SyncLevelWarn, "cloud was newer"},
	}
	for _, tc := range cases {
		o := tc.o
		fillMessage(&o)
		if o.Level != tc.wantLevel {
			t.Errorf("%s/%s: level %q want %q", o.Resource, o.Action, o.Level, tc.wantLevel)
		}
		if !strings.Contains(o.Message, tc.wantSubstr) {
			t.Errorf("%s/%s: message %q missing %q", o.Resource, o.Action, o.Message, tc.wantSubstr)
		}
	}
}

func TestSkippedOutcome(t *testing.T) {
	o := skippedOutcome("contacts", "no local identity yet")
	if o.Action != SyncSkipped || o.Level != SyncLevelWarn {
		t.Fatalf("skipped outcome shape wrong: %+v", o)
	}
	if o.Skipped != "no local identity yet" || !strings.Contains(o.Message, "no local identity yet") {
		t.Fatalf("skipped reason not carried: %+v", o)
	}
}
