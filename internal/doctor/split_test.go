package doctor

import (
	"reflect"
	"testing"
)

// The value is what systemctl show printed for a unit with these drop-in file
// names (systemd 255): a name with a space, a quote, a backslash, a dollar
// sign, a backquote, a single quote and a tab.
const capturedDropInPaths = `"/etc/systemd/system/keepwatch-check.service.d/a b.conf" "/etc/systemd/system/keepwatch-check.service.d/bq\` + "`" + `x.conf" "/etc/systemd/system/keepwatch-check.service.d/bs\\x.conf" "/etc/systemd/system/keepwatch-check.service.d/d\$x.conf" "/etc/systemd/system/keepwatch-check.service.d/q\"x.conf" "/etc/systemd/system/keepwatch-check.service.d/sq'x.conf" "/etc/systemd/system/keepwatch-check.service.d/tab\tx.conf"`

func TestSplitQuoted(t *testing.T) {
	const d = "/etc/systemd/system/keepwatch-check.service.d/"
	for name, c := range map[string]struct {
		in   string
		want []string
	}{
		"empty":           {"", nil},
		"blanks":          {"  \n", nil},
		"one":             {d + "o.conf", []string{d + "o.conf"}},
		"two":             {d + "a.conf " + d + "b.conf", []string{d + "a.conf", d + "b.conf"}},
		"quoted space":    {`"` + d + `a b.conf"`, []string{d + "a b.conf"}},
		"quoted, plain":   {`"` + d + `a b.conf" ` + d + "c.conf", []string{d + "a b.conf", d + "c.conf"}},
		"plain, quoted":   {d + `c.conf "` + d + `a b.conf"`, []string{d + "c.conf", d + "a b.conf"}},
		"not closed":      {`"` + d + `a b.conf`, []string{d + "a b.conf"}},
		"empty quotes":    {`"" x`, []string{"", "x"}},
		"trailing escape": {`"a\`, []string{`a\`}},
		"captured": {capturedDropInPaths, []string{
			d + "a b.conf", d + "bq`x.conf", d + `bs\x.conf`, d + "d$x.conf", d + `q"x.conf`, d + "sq'x.conf", d + "tab\tx.conf"}},
	} {
		if got := splitQuoted(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

func TestListPathsQuotesWhatNeedsIt(t *testing.T) {
	if got, want := listPaths([]string{"/a/b.conf", "/a/c d.conf", `/a/e"f.conf`}), `/a/b.conf "/a/c d.conf" "/a/e\"f.conf"`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
