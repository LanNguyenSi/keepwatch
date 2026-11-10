package state

import (
	"strings"
	"testing"
	"time"
)

func withDelivery(d *Delivery) *State {
	st := sample()
	st.Delivery = d
	return st
}

func TestDeliveryRecordRoundTripsAndIsOmittedWhenAbsent(t *testing.T) {
	s, _ := newStore(t)
	mustSave(t, s, sample())
	lr, err := s.Load()
	if err != nil || lr.State.Delivery != nil {
		t.Fatalf("%+v %v", lr, err)
	}
	b, _ := Marshal(sample())
	if strings.Contains(string(b), "delivery") {
		t.Errorf("a state without a record holds the field:\n%s", b)
	}

	for _, kind := range []string{DeliveryCheck, DeliveryWeekly, DeliveryBaseline} {
		mustSave(t, s, withDelivery(&Delivery{FailedAt: t0, Failures: 1, Kind: kind}))
		if lr, err := s.Load(); err != nil || lr.State == nil || lr.State.Delivery == nil || lr.State.Delivery.Kind != kind {
			t.Errorf("kind %q: %+v %v", kind, lr, err)
		}
	}
	want := &Delivery{FailedAt: t0.Add(time.Hour), Failures: 3, Kind: DeliveryCheck, Reason: "ntfy: HTTP 503 (after 2 attempts)"}
	mustSave(t, s, withDelivery(want))
	lr, err = s.Load()
	if err != nil || lr.Problem != "" || lr.State == nil || lr.State.Delivery == nil {
		t.Fatalf("%+v %v", lr, err)
	}
	if got := lr.State.Delivery; !got.FailedAt.Equal(want.FailedAt) || got.Failures != 3 || got.Kind != DeliveryCheck || got.Reason != want.Reason {
		t.Errorf("loaded %+v", got)
	}
}

func TestInvalidDeliveryRecordMakesTheFileUnusable(t *testing.T) {
	ok := Delivery{FailedAt: t0, Failures: 1, Kind: DeliveryWeekly, Reason: "r"}
	cases := map[string]func(d *Delivery){
		"unknown kind":   func(d *Delivery) { d.Kind = "other" },
		"empty kind":     func(d *Delivery) { d.Kind = "" },
		"zero failures":  func(d *Delivery) { d.Failures = 0 },
		"negative":       func(d *Delivery) { d.Failures = -1 },
		"huge failures":  func(d *Delivery) { d.Failures = maxDeliveryFailures + 1 },
		"no time":        func(d *Delivery) { d.FailedAt = time.Time{} },
		"long reason":    func(d *Delivery) { d.Reason = strings.Repeat("x", maxDeliveryReason+1) },
		"very long text": func(d *Delivery) { d.Reason = strings.Repeat("x", 1<<20) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			s, dir := newStore(t)
			d := ok
			mut(&d)
			b, err := Marshal(withDelivery(&d))
			if err != nil {
				t.Fatal(err)
			}
			writeStateFile(t, s, dir, string(b))
			lr, err := s.Load()
			if err != nil || lr.State != nil || !strings.Contains(lr.Problem, "delivery") {
				t.Errorf("%+v %v", lr, err)
			}
		})
	}
	// The limits themselves are valid.
	for name, d := range map[string]Delivery{
		"longest reason": {FailedAt: t0, Failures: 1, Kind: DeliveryCheck, Reason: strings.Repeat("x", maxDeliveryReason)},
		"most failures":  {FailedAt: t0, Failures: maxDeliveryFailures, Kind: DeliveryCheck},
	} {
		d := d
		if err := validateDelivery(&d); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := validateDelivery(nil); err != nil {
		t.Error(err)
	}
}

func TestDeliveryRecordHasNoUnknownFields(t *testing.T) {
	s, dir := newStore(t)
	b, _ := Marshal(withDelivery(&Delivery{FailedAt: t0, Failures: 1, Kind: DeliveryCheck, Reason: "r"}))
	doc := strings.Replace(string(b), `"failures": 1,`, `"failures": 1, "message": "the body",`, 1)
	if doc == string(b) {
		t.Fatalf("no failures field:\n%s", b)
	}
	writeStateFile(t, s, dir, doc)
	if lr, err := s.Load(); err != nil || lr.State != nil || lr.Problem == "" {
		t.Errorf("%+v %v", lr, err)
	}
}
