package engine

import (
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// applyExceptions on a failing result that carries no evidence: probes always
// attach evidence to a failure, but the rule must hold without it. Only a
// whole-check exception can cover such a result; a match has nothing to match.
func TestApplyExceptionsWithoutEvidence(t *testing.T) {
	exp := func(match string) config.Exception {
		return config.Exception{Check: "a.b", Match: match, Reason: "why", Expires: time.Now()}
	}
	cases := []struct {
		name   string
		active []config.Exception
		want   result.Status
	}{
		{"no exception", nil, result.Fail},
		{"match only", []config.Exception{exp("x")}, result.Fail},
		{"whole check", []config.Exception{exp("")}, result.Excepted},
		{"other check", []config.Exception{{Check: "c.d", Reason: "why"}}, result.Fail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := result.Result{CheckID: "a.b", Status: result.Fail, Summary: "s"}
			applyExceptions(&r, c.active, nil)
			if r.Status != c.want {
				t.Fatalf("status %s, want %s", r.Status, c.want)
			}
			if (c.want == result.Excepted) != (len(r.ExceptionReasons) == 1) {
				t.Fatalf("reasons %v", r.ExceptionReasons)
			}
		})
	}
}

func TestApplyExceptionsWithWarnings(t *testing.T) {
	warn := []result.Evidence{{Subject: "w", Detail: "look"}}
	fail := func() result.Result {
		return result.Result{CheckID: "a.b", Status: result.Fail, Summary: "s", Evidence: []result.Evidence{{Subject: "x"}, {Subject: "y"}}}
	}
	exp := func(match string) config.Exception {
		return config.Exception{Check: "a.b", Match: match, Reason: "why", Expires: time.Now()}
	}
	t.Run("all failing items covered: warn with the warnings", func(t *testing.T) {
		r := fail()
		applyExceptions(&r, []config.Exception{exp("x"), exp("y")}, warn)
		if r.Status != result.Warn || len(r.Evidence) != 1 || r.Evidence[0].Subject != "w" || r.Evidence[0].Excepted {
			t.Fatalf("result %+v", r)
		}
		if r.Summary != "s (failing items excepted: why); 1 warning(s) remain" {
			t.Fatalf("summary %q", r.Summary)
		}
	})
	t.Run("whole check covered", func(t *testing.T) {
		r := fail()
		applyExceptions(&r, []config.Exception{exp("")}, warn)
		if r.Status != result.Warn {
			t.Fatalf("status %s", r.Status)
		}
	})
	t.Run("some failing items covered: fail, evidence unchanged", func(t *testing.T) {
		r := fail()
		applyExceptions(&r, []config.Exception{exp("x")}, warn)
		if r.Status != result.Fail || len(r.Evidence) != 2 || !r.Evidence[0].Excepted || r.Evidence[1].Excepted {
			t.Fatalf("result %+v", r)
		}
	})
	t.Run("nothing covered: fail", func(t *testing.T) {
		r := fail()
		applyExceptions(&r, []config.Exception{exp("z")}, warn)
		if r.Status != result.Fail || len(r.ExceptionReasons) != 0 {
			t.Fatalf("result %+v", r)
		}
	})
	t.Run("no warnings: excepted", func(t *testing.T) {
		r := fail()
		applyExceptions(&r, []config.Exception{exp("")}, nil)
		if r.Status != result.Excepted {
			t.Fatalf("status %s", r.Status)
		}
	})
	t.Run("a result that did not fail is not touched", func(t *testing.T) {
		for _, st := range []result.Status{result.Pass, result.Warn, result.Error, result.Skipped} {
			r := result.Result{CheckID: "a.b", Status: st, Summary: "s"}
			applyExceptions(&r, []config.Exception{exp("")}, warn)
			if r.Status != st || r.Summary != "s" {
				t.Fatalf("%s: %+v", st, r)
			}
		}
	})
}
