package pyzor

import (
	"errors"
	"testing"
)

// TestHitVerdictMatrix pins the reference-pyzor semantics:
// spam iff all servers OK AND some Count>rCount AND no WL-Count>wlCount.
func TestHitVerdictMatrix(t *testing.T) {
	ok := func(count, wl int) ServerResult {
		return ServerResult{Code: 200, Count: count, WLCount: wl}
	}
	cases := []struct {
		name            string
		servers         []ServerResult
		rCount, wlCount int
		want            bool
	}{
		{"empty", nil, 0, 0, false},
		{"single hit", []ServerResult{ok(10, 0)}, 1, 1, true},
		{"single miss", []ServerResult{ok(0, 0)}, 1, 1, false},
		{"two count=1 no sum", []ServerResult{ok(1, 0), ok(1, 0)}, 1, 0, false},
		{"whitelist on same server clears", []ServerResult{ok(10, 5)}, 1, 1, false},
		{"whitelist on OTHER server clears", []ServerResult{ok(10, 0), ok(0, 2)}, 1, 1, false},
		{"server error -> not all_ok", []ServerResult{ok(10, 0), {Err: errors.New("timeout")}}, 1, 0, false},
		{"non-200 -> not all_ok", []ServerResult{ok(10, 0), {Code: 400}}, 1, 0, false},
	}
	for _, c := range cases {
		got := CheckResult{Servers: c.servers}.Hit(c.rCount, c.wlCount)
		if got != c.want {
			t.Errorf("%s: Hit=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestRequireCounts(t *testing.T) {
	full := &response{fields: map[string]string{"Count": "3", "WL-Count": "0"}}
	if err := full.requireCounts(); err != nil {
		t.Errorf("complete counts should pass: %v", err)
	}
	bad := []*response{
		{fields: map[string]string{"WL-Count": "0"}},               // missing Count
		{fields: map[string]string{"Count": "3"}},                  // missing WL-Count
		{fields: map[string]string{"Count": "x", "WL-Count": "0"}}, // nonnumeric Count
	}
	for i, r := range bad {
		if err := r.requireCounts(); err == nil {
			t.Errorf("case %d: expected error for malformed counts", i)
		}
	}
}
