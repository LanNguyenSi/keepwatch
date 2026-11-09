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
			applyExceptions(&r, c.active)
			if r.Status != c.want {
				t.Fatalf("status %s, want %s", r.Status, c.want)
			}
			if (c.want == result.Excepted) != (len(r.ExceptionReasons) == 1) {
				t.Fatalf("reasons %v", r.ExceptionReasons)
			}
		})
	}
}
