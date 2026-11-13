package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// The table test for the fingerprint comparison: every form the two sides
// can carry maps onto one value. Config side: authorized_keys.expected
// entries, with or without the "SHA256:" prefix and with or without base64
// padding (the stage-0 authorized_keys probe trims padding the same way).
// Log side: the fingerprint of an "Accepted publickey" line, with the
// prefix and without padding.
func TestNormalizeKeyFPTable(t *testing.T) {
	forms := []string{
		"SHA256:AAAABBBB",  // log form, as sshd and ssh-keygen print it
		"SHA256:AAAABBBB=", // config form with padding
		"SHA256:AAAABBBB==",
		"AAAABBBB",  // prefixless config form
		"AAAABBBB=", // prefixless with padding
	}
	for _, a := range forms {
		for _, b := range forms {
			if normalizeKeyFP(a) != normalizeKeyFP(b) {
				t.Errorf("%q and %q normalize differently", a, b)
			}
		}
	}
	if got := normalizeKeyFP("AAA=ABBB"); got != "AAA=ABBB" {
		t.Errorf("padding inside the text was trimmed: %q", got)
	}
	// An empty fingerprint is never accepted: both empty forms normalize to
	// the empty string, which the callers refuse.
	if normalizeKeyFP("SHA256:") != "" || normalizeKeyFP("=") != "" {
		t.Error("empty forms must normalize to empty")
	}
	if normalizeKeyFP("SHA256:AAAABBBB") == normalizeKeyFP("SHA256:AAAABBBC") {
		t.Error("different keys must not collide")
	}
}

func TestBaselineKnownAndAdd(t *testing.T) {
	b := NewBaseline(t0)
	if b.KnownIP("bob", "1.2.3.4") || b.KnownKey("bob", "SHA256:x") {
		t.Fatal("unknown user must not be known")
	}
	if !b.AddIP("bob", "1.2.3.4") || !b.AddKey("bob", "SHA256:x") {
		t.Fatal("adds")
	}
	if !b.KnownIP("bob", "1.2.3.4") || !b.KnownKey("bob", "x") || !b.KnownKey("bob", "SHA256:x=") {
		t.Fatal("entries not known after add")
	}
	// A different user does not share the entries.
	if b.KnownIP("alice", "1.2.3.4") {
		t.Fatal("users must not share addresses")
	}
	// Degenerate entries are refused everywhere.
	for _, bad := range []string{"", strings.Repeat("e", maxBaselineEntryLen+1)} {
		if b.AddIP("bob", bad) || b.KnownIP("bob", bad) {
			t.Errorf("address %q must be refused", bad)
		}
		if b.AddKey("bob", bad) || b.KnownKey("bob", bad) {
			t.Errorf("key %q must be refused", bad)
		}
	}
	if b.AddKey("bob", "SHA256:") || b.KnownKey("bob", "SHA256:") {
		t.Error("empty fingerprint must be refused")
	}
	if b.AddIP(strings.Repeat("u", maxBaselineUserLen+1), "9.9.9.9") {
		t.Error("user name over the length bound must be refused")
	}
	if _, exists := b.users[strings.Repeat("u", maxBaselineUserLen+1)]; exists {
		t.Error("an over-long user must not be created")
	}
	if b.AddIP("", "9.9.9.9") || b.AddKey("", "SHA256:x") {
		t.Error("empty user name must be refused")
	}
	if _, exists := b.users[""]; exists {
		t.Error("an empty user must not be created")
	}
	badUser := "bob\xff\xfe" // not valid UTF-8
	if b.AddIP(badUser, "9.9.9.9") || b.AddKey(badUser, "SHA256:x") {
		t.Error("user name that is not valid UTF-8 must be refused")
	}
	if _, exists := b.users[badUser]; exists {
		t.Error("a non-UTF-8 user must not be created")
	}
	if len(b.users["bob"].ips) != 1 || len(b.users["bob"].keys) != 1 {
		t.Fatalf("a refused entry must not be stored: %+v", b.users["bob"])
	}
}

func TestBaselineLearningStart(t *testing.T) {
	b := NewBaseline(t0)
	if !b.LearningStart().Equal(t0) {
		t.Fatalf("LearningStart = %v", b.LearningStart())
	}
}

func TestBaselineCaps(t *testing.T) {
	b := NewBaseline(t0)
	// Entries per user: the sum of ips and keys of one user is capped, an
	// entry already known does not count again, and a refused add is not
	// stored.
	for i := 0; i < BaselineEntriesPerUser; i++ {
		ok := b.AddIP("bob", fmt.Sprintf("10.%d.%d.1", i/256, i%256))
		if !ok {
			t.Fatalf("entry %d refused below the cap", i)
		}
	}
	if !b.AddIP("bob", "10.0.0.1") {
		t.Fatal("a known entry must always re-add")
	}
	if b.AddIP("bob", "10.1.1.1") || b.KnownIP("bob", "10.1.1.1") {
		t.Fatal("entry over the per-user cap must be refused and not stored")
	}
	if b.AddKey("bob", "SHA256:new") || b.KnownKey("bob", "SHA256:new") {
		t.Fatal("keys share the per-user cap with addresses")
	}
	// Users: the cap counts whole users and an over-cap user is not
	// created.
	for i := 0; i < BaselineMaxUsers-1; i++ {
		if !b.AddIP(fmt.Sprintf("u%d", i), "192.0.2.1") {
			t.Fatalf("user %d refused below the cap", i)
		}
	}
	if b.AddIP("overflow", "192.0.2.1") {
		t.Fatal("user over the cap must be refused")
	}
	if _, exists := b.users["overflow"]; exists {
		t.Fatal("a refused user must not be created")
	}
}

func TestBaselineMarshalRoundTrip(t *testing.T) {
	b := NewBaseline(t0.Add(3 * time.Hour))
	b.AddIP("bob", "203.0.113.9")
	b.AddIP("bob", "2001:db8::1")
	b.AddKey("bob", "SHA256:aaaabbbb=")
	b.AddIP("alice", "192.0.2.7")
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, raw)
	}
	if !again.LearningStart().Equal(b.LearningStart()) {
		t.Fatal("learning start lost")
	}
	if !again.KnownIP("bob", "203.0.113.9") || !again.KnownIP("bob", "2001:db8::1") ||
		!again.KnownKey("bob", "SHA256:aaaabbbb") || !again.KnownIP("alice", "192.0.2.7") {
		t.Fatalf("entries lost: %+v", again)
	}
	if again.KnownIP("alice", "203.0.113.9") {
		t.Fatal("users mixed up")
	}
	// Deterministic output: the same baseline marshals byte-identically,
	// so a written file can be diffed.
	second, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(second) {
		t.Fatal("Marshal is not deterministic")
	}
	// The wire form carries the documented field names.
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema_version"] != float64(BaselineSchemaVersion) {
		t.Errorf("schema_version = %v", doc["schema_version"])
	}
	if _, ok := doc["learning_start"]; !ok {
		t.Error("no learning_start")
	}
	users, ok := doc["users"].([]any)
	if !ok || len(users) != 2 || users[0].(map[string]any)["user"] != "alice" {
		t.Errorf("users not sorted as a list: %v", doc["users"])
	}
	// The order is by name, not by insertion or map order: add many users
	// and check the written list is sorted (a map iterated unsorted would
	// almost surely not be).
	b2 := NewBaseline(t0)
	for _, name := range []string{"m9", "m1", "m7", "m3", "m12", "m0", "m11", "m4", "m8", "m10", "m5", "m2", "m6", "m13"} {
		if !b2.AddIP(name, "192.0.2.1") {
			t.Fatal("AddIP")
		}
	}
	raw2, err := b2.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var at int
	for _, name := range []string{"m0", "m1", "m10", "m11", "m12", "m13", "m2", "m3", "m4", "m5", "m6", "m7", "m8", "m9"} {
		marker := `"user":"` + name + `"`
		next := strings.Index(string(raw2)[at:], marker)
		if next < 0 {
			t.Fatalf("user %s missing or out of order in %s", name, raw2)
		}
		at += next
	}
	// The entry lists are sorted the same way (insertion order is not).
	b3 := NewBaseline(t0)
	ips := []string{}
	for j := 0; j < 14; j++ {
		ip := fmt.Sprintf("10.0.%d.1", j)
		ips = append(ips, ip)
		if !b3.AddIP("zed", ip) {
			t.Fatal("AddIP")
		}
	}
	sort.Strings(ips)
	raw3, err := b3.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	at = 0
	for _, ip := range ips {
		next := strings.Index(string(raw3)[at:], `"`+ip+`"`)
		if next < 0 {
			t.Fatalf("ip %s missing or out of order in %s", ip, raw3)
		}
		at += next
	}
}

// A baseline restored without a LearningStart (the zero instant) is past
// its learning phase. The learning latch round-trips: a baseline whose
// phase ended loads ended, and one that never saw the end loads open,
// including from a file that predates the field.
func TestBaselineLearningDoneRoundTrip(t *testing.T) {
	b := NewBaseline(t0)
	if b.LearningDone() {
		t.Fatal("a fresh baseline has not ended its learning phase")
	}
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Unmarshal(raw)
	if err != nil || again.LearningDone() {
		t.Fatalf("unset latch: %v %v", err, again.LearningDone())
	}
	b.MarkLearningDone()
	if !b.LearningDone() {
		t.Fatal("MarkLearningDone")
	}
	raw, err = b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["learning_done"] != true {
		t.Errorf("learning_done = %v in %s", doc["learning_done"], raw)
	}
	again, err = Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !again.LearningDone() || !again.LearningStart().Equal(t0) {
		t.Fatal("learning latch lost in the round trip")
	}
	// A file without the field (an older writer) loads open.
	again, err = Unmarshal([]byte(`{"schema_version":1,"learning_start":"2026-01-02T03:04:05Z","users":[]}`))
	if err != nil || again.LearningDone() {
		t.Fatalf("missing latch field: %v %v", err, again != nil && again.LearningDone())
	}
}

func TestUnmarshalSchemaAndErrors(t *testing.T) {
	cases := []struct {
		name string
		data string
		want error
	}{
		{"newer schema", `{"schema_version":2,"learning_start":"2026-01-02T03:04:05Z","users":[]}`, ErrBaselineSchema},
		{"zero schema", `{"schema_version":0,"users":[]}`, ErrBaselineSchema},
		{"missing schema", `{"users":[]}`, ErrBaselineSchema},
		{"not json", `nonsense`, errBaselineCorrupt},
		{"truncated", `{"schema_version":1,"users":[`, errBaselineCorrupt},
		{"users not a list", `{"schema_version":1,"users":7}`, errBaselineCorrupt},
		{"empty user name", `{"schema_version":1,"users":[{"user":"","ips":[]}]}`, errBaselineCorrupt},
		{"duplicate user", `{"schema_version":1,"users":[{"user":"bob","ips":["1.2.3.4"]},{"user":"bob","ips":[]}]}`, errBaselineCorrupt},
		{"duplicate entry", `{"schema_version":1,"users":[{"user":"bob","ips":["1.2.3.4","1.2.3.4"]}]}`, errBaselineCorrupt},
		{"empty entry", `{"schema_version":1,"users":[{"user":"bob","ips":[""]}]}`, errBaselineCorrupt},
		{"empty key", `{"schema_version":1,"users":[{"user":"bob","keys":["SHA256:"]}]}`, errBaselineCorrupt},
		{"oversized entry", `{"schema_version":1,"users":[{"user":"bob","ips":["` + strings.Repeat("9", maxBaselineEntryLen+1) + `"]}]}`, errBaselineCorrupt},
		{"oversized key", `{"schema_version":1,"users":[{"user":"bob","keys":["SHA256:` + strings.Repeat("k", maxBaselineEntryLen+1) + `"]}]}`, errBaselineCorrupt},
		{"duplicate key", `{"schema_version":1,"users":[{"user":"bob","keys":["SHA256:aaa","SHA256:aaa"]}]}`, errBaselineCorrupt},
		{"oversized user", `{"schema_version":1,"users":[{"user":"` + strings.Repeat("u", maxBaselineUserLen+1) + `","ips":[]}]}`, errBaselineCorrupt},
	}
	for _, tc := range cases {
		b, err := Unmarshal([]byte(tc.data))
		if err == nil {
			t.Errorf("%s: no error, got %+v", tc.name, b)
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: error %v does not wrap %v", tc.name, err, tc.want)
		}
	}
}

func TestUnmarshalCapCounts(t *testing.T) {
	ips := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf("10.%d.%d.1", i/256, i%256))
		}
		return `["` + strings.Join(parts, `","`) + `"]`
	}
	keys := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf("SHA256:k%04d", i))
		}
		return `["` + strings.Join(parts, `","`) + `"]`
	}
	// One entry over the per-user cap is refused; at the cap it loads.
	_, err := Unmarshal([]byte(`{"schema_version":1,"users":[{"user":"bob","ips":` + ips(BaselineEntriesPerUser+1) + `}]}`))
	if !errors.Is(err, errBaselineCorrupt) {
		t.Errorf("over-cap entries: %v", err)
	}
	b, err := Unmarshal([]byte(`{"schema_version":1,"users":[{"user":"bob","ips":` + ips(BaselineEntriesPerUser) + `}]}`))
	if err != nil || !b.KnownIP("bob", "10.0.0.1") {
		t.Errorf("at-cap entries: %v %+v", err, b)
	}
	// Keys count against the per-user cap together with the addresses:
	// ips plus keys one over the cap is refused, at the cap it loads.
	_, err = Unmarshal([]byte(`{"schema_version":1,"users":[{"user":"bob","ips":` +
		ips(BaselineEntriesPerUser/2) + `,"keys":` + keys(BaselineEntriesPerUser/2+1) + `}]}`))
	if !errors.Is(err, errBaselineCorrupt) {
		t.Errorf("ips plus keys over the cap: %v", err)
	}
	b, err = Unmarshal([]byte(`{"schema_version":1,"users":[{"user":"bob","ips":` +
		ips(BaselineEntriesPerUser/2) + `,"keys":` + keys(BaselineEntriesPerUser/2) + `}]}`))
	if err != nil || !b.KnownIP("bob", "10.0.0.1") || !b.KnownKey("bob", "SHA256:k0000") {
		t.Errorf("ips plus keys at the cap: %v %+v", err, b)
	}
	// One user over the user cap is refused; exactly at the cap it loads.
	var users, usersAt []string
	for i := 0; i < BaselineMaxUsers+1; i++ {
		users = append(users, fmt.Sprintf(`{"user":"u%d","ips":["192.0.2.1"]}`, i))
		if i < BaselineMaxUsers {
			usersAt = append(usersAt, fmt.Sprintf(`{"user":"v%d","ips":["192.0.2.2"]}`, i))
		}
	}
	if _, err := Unmarshal([]byte(`{"schema_version":1,"users":[` + strings.Join(users, ",") + `]}`)); !errors.Is(err, errBaselineCorrupt) {
		t.Errorf("over-cap users: %v", err)
	}
	b, err = Unmarshal([]byte(`{"schema_version":1,"users":[` + strings.Join(usersAt, ",") + `]}`))
	if err != nil {
		t.Fatalf("at-cap users: %v", err)
	}
	b.mu.Lock()
	n := len(b.users)
	b.mu.Unlock()
	if n != BaselineMaxUsers || !b.KnownIP("v0", "192.0.2.2") || !b.KnownIP(fmt.Sprintf("v%d", BaselineMaxUsers-1), "192.0.2.2") {
		t.Errorf("at-cap users: %d users loaded", n)
	}
	// An oversized document is refused before it is parsed. The size
	// bound admits a worst-case marshal at the caps (see its
	// derivation), so a refusal of such a large input must come from
	// the bound itself: the error names the byte count. (The input is
	// this large because the bound is.)
	if _, err := Unmarshal(make([]byte, maxBaselineUnmarshalBytes+1)); err == nil || !strings.Contains(err.Error(), "bytes exceeds") {
		t.Errorf("oversized document: %v", err)
	}
}

// Marshal at the caps, with entries of realistic length, produces a
// document Unmarshal accepts: the size bound is derived from the caps
// and the length bounds, so a baseline can never outgrow its own load
// bound.
func TestBaselineMarshalAtCapsRoundTrip(t *testing.T) {
	b := NewBaseline(t0)
	for u := 0; u < BaselineMaxUsers; u++ {
		name := fmt.Sprintf("user%d", u)
		for e := 0; e < BaselineEntriesPerUser; e++ {
			var ok bool
			if e%2 == 0 {
				ok = b.AddIP(name, fmt.Sprintf("2001:db8:%x:%x::%x", u, e, e))
			} else {
				ok = b.AddKey(name, fmt.Sprintf("SHA256:%s%04d%04d", "AbCdEfGhIjKlMnOpQrStUvWxYz012345678", u, e))
			}
			if !ok {
				t.Fatalf("entry %d of user %d refused below the cap", e, u)
			}
		}
	}
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	again, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("a marshal at the caps must load: %d bytes, %v", len(raw), err)
	}
	if !again.KnownIP("user0", "2001:db8:0:0::0") || !again.KnownKey("user0", "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz01234567800000001") {
		t.Fatal("first user lost")
	}
	last := fmt.Sprintf("user%d", BaselineMaxUsers-1)
	if !again.KnownIP(last, fmt.Sprintf("2001:db8:%x:%x::%x", BaselineMaxUsers-1, 0, 0)) ||
		!again.KnownKey(last, fmt.Sprintf("SHA256:%s%04d%04d", "AbCdEfGhIjKlMnOpQrStUvWxYz012345678", BaselineMaxUsers-1, 1)) {
		t.Fatal("last user lost")
	}
	again.mu.Lock()
	n := len(again.users)
	again.mu.Unlock()
	if n != BaselineMaxUsers {
		t.Fatalf("%d users loaded", n)
	}
}

// A baseline file written with config-form fingerprints matches log-form
// lookups after one load, so seeded keys survive a restart.
func TestUnmarshalNormalizesKeys(t *testing.T) {
	b, err := Unmarshal([]byte(`{"schema_version":1,"users":[{"user":"carol","keys":["SHA256:xyz1234=","AAAABBBB=="]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !b.KnownKey("carol", "SHA256:xyz1234") || !b.KnownKey("carol", "SHA256:AAAABBBB") {
		t.Fatal("config-form keys must match log-form lookups")
	}
	// Re-marshalling keeps the normalized form, and a second load agrees.
	raw, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `=`) {
		t.Errorf("normalized keys must not carry padding: %s", raw)
	}
	b2, err := Unmarshal(raw)
	if err != nil || !b2.KnownKey("carol", "xyz1234") {
		t.Fatalf("second load: %v", err)
	}
}
