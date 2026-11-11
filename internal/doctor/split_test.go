package doctor

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// The value is what systemctl show printed for a unit with these drop-in file
// names (systemd 255): a name with a space, a quote, a backslash, a dollar
// sign, a backquote, a single quote and a tab.
const capturedDropInPaths = `"/etc/systemd/system/keepwatch-check.service.d/a b.conf" "/etc/systemd/system/keepwatch-check.service.d/bq\` + "`" + `x.conf" "/etc/systemd/system/keepwatch-check.service.d/bs\\x.conf" "/etc/systemd/system/keepwatch-check.service.d/d\$x.conf" "/etc/systemd/system/keepwatch-check.service.d/q\"x.conf" "/etc/systemd/system/keepwatch-check.service.d/sq'x.conf" "/etc/systemd/system/keepwatch-check.service.d/tab\tx.conf"`

// dropInDir is the directory of the captures.
const dropInDir = "/etc/systemd/system/keepwatch-check.service.d/"

// capturedEntry is one entry of a DropInPaths value as systemctl printed it.
type capturedEntry struct {
	// quoted: systemctl put the entry in double quotes.
	quoted bool
	// emitted is the file name as systemctl wrote it, behind the directory.
	emitted string
	// name is the file name on disk.
	name string
}

// capturedDropIns is the DropInPaths value "systemctl show" printed for
// keepwatch-check.service with 39 drop-ins whose names hold every kind of byte
// a file name can: blanks, the characters systemctl puts a backslash before,
// each control character it has a letter for, control characters it writes as
// octal numbers (ESC, DEL, 0x01), UTF-8 it prints as it is (among it a C1
// control, a character that reverses the direction of the text, a line
// separator and one that draws nothing) and a name that itself holds a
// backslash and digits. Captured on Ubuntu 22.04 (systemd 249) and on Ubuntu
// 24.04 (systemd 255): both printed the same bytes, in this order. A name that
// is not valid UTF-8 is not in it, because systemctl show fails for such a unit.
var capturedDropIns = []capturedEntry{
	{true, `a b.conf`, "a b.conf"},
	{true, `amp&x.conf`, "amp&x.conf"},
	{true, `bel\a.conf`, "bel\a.conf"},
	{true, `bel\ax.conf`, "bel\ax.conf"},
	{false, "bidi\u202ex.conf", "bidi\u202ex.conf"},
	{true, "bq\\`x.conf", "bq`x.conf"},
	{true, `bs\\x.conf`, "bs\\x.conf"},
	{true, `bsp\bx.conf`, "bsp\bx.conf"},
	{false, "c1\u0085x.conf", "c1\u0085x.conf"},
	{false, `cb{x.conf`, "cb{x.conf"},
	{true, `cr\rok   units: fine.conf`, "cr\rok   units: fine.conf"},
	{true, `cr\rx.conf`, "cr\rx.conf"},
	{false, "csi\u009bx.conf", "csi\u009bx.conf"},
	{true, `d\$x.conf`, "d$x.conf"},
	{true, `del\177.conf`, "del\x7f.conf"},
	{true, `del\177x.conf`, "del\x7fx.conf"},
	{false, `eq=x.conf`, "eq=x.conf"},
	{true, `esc\033[31mred.conf`, "esc\x1b[31mred.conf"},
	{true, `esc\033x.conf`, "esc\x1bx.conf"},
	{true, `ff\fx.conf`, "ff\fx.conf"},
	{false, `hash#x.conf`, "hash#x.conf"},
	{false, "ls\u2028x.conf", "ls\u2028x.conf"},
	{false, "nbsp\u00a0x.conf", "nbsp\u00a0x.conf"},
	{true, `nl\nok   units: fine.conf`, "nl\nok   units: fine.conf"},
	{true, `nl\nx.conf`, "nl\nx.conf"},
	{true, `one\001.conf`, "one\x01.conf"},
	{true, `one\001x.conf`, "one\x01x.conf"},
	{false, `pct%x.conf`, "pct%x.conf"},
	{false, `plain.conf`, "plain.conf"},
	{true, `q\"x.conf`, "q\"x.conf"},
	{true, `semi;x.conf`, "semi;x.conf"},
	{true, `sq'x.conf`, "sq'x.conf"},
	{true, `tab\tx.conf`, "tab\tx.conf"},
	{false, `tilde~x.conf`, "tilde~x.conf"},
	{false, "utf\u00e9.conf", "utf\u00e9.conf"},
	{false, "utf\u00e9x.conf", "utf\u00e9x.conf"},
	{true, `vt\vx.conf`, "vt\vx.conf"},
	{true, `x7\\1017.conf`, "x7\\1017.conf"},
	{false, "zw\u200bx.conf", "zw\u200bx.conf"},
}

// capturedSHA256 is the SHA-256 of the captured value (what follows
// "DropInPaths=", without the line feed), so that the table above cannot drift
// from what systemctl printed.
const capturedSHA256 = "7476ea4baa8a0754646ca8c922134bba7e0e9c87800bc976575c148fd30ee37d"

// captured returns the value as systemctl printed it and the names on disk.
func captured() (value string, paths []string) {
	var tokens []string
	for _, e := range capturedDropIns {
		tok := dropInDir + e.emitted
		if e.quoted {
			tok = `"` + tok + `"`
		}
		tokens = append(tokens, tok)
		paths = append(paths, dropInDir+e.name)
	}
	return strings.Join(tokens, " "), paths
}

func TestSplitQuoted(t *testing.T) {
	const d = dropInDir
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

// What systemd 249 and 255 printed is read back into the names on disk, byte
// for byte.
func TestSplitQuotedReadsWhatSystemctlPrinted(t *testing.T) {
	value, want := captured()
	if sum := sha256.Sum256([]byte(value)); hex.EncodeToString(sum[:]) != capturedSHA256 {
		t.Fatalf("the table is not the captured value any more (SHA-256 %x)", sum)
	}
	got := splitQuoted(value)
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d (%s): got %q, want %q", i, capturedDropIns[i].emitted, got[i], want[i])
		}
	}
}

// The escapes of systemd, one by one: the letters, the octal and the
// hexadecimal number, the characters a backslash only protects, and what is
// not an escape.
func TestSplitQuotedEscapes(t *testing.T) {
	for in, want := range map[string]string{
		`\a`: "\a", `\b`: "\b", `\f`: "\f", `\n`: "\n", `\r`: "\r", `\t`: "\t", `\v`: "\v",
		`\\`: `\`, `\"`: `"`, `\'`: `'`, `\$`: `$`, "\\`": "`",
		// Octal: three digits, up to 0377.
		`\033`: "\x1b", `\177`: "\x7f", `\001`: "\x01", `\101`: "A", `\377`: "\xff", `\000`: "\x00",
		`\303\251`: "\u00e9",
		`\0331`:    "\x1b1",
		// Hexadecimal: x and two digits, either case.
		`\x1b`: "\x1b", `\x7F`: "\x7f", `\x41`: "A", `\xff`: "\xff", `\x411`: "A1",
		// Not a number: the backslash protects one byte, the rest is text.
		`\400`: "400", `\777`: "777", `\08`: "08", `\8`: "8", `\12`: "12", `\1`: "1", `\x4`: "x4", `\xzz`: "xzz", `\x`: "x",
		`\+12`: "+12", `\x+1`: "x+1", `\-01`: "-01",
		// A backslash that was itself escaped starts nothing.
		`\\033`: `\033`, `\\x41`: `\x41`, `\\n`: `\n`,
		// An unknown letter stands for itself.
		`\q`: "q", `\e`: "e", `\s`: "s",
	} {
		if got := splitQuoted(`"/d/a` + in + `z"`); !reflect.DeepEqual(got, []string{"/d/a" + want + "z"}) {
			t.Errorf("%s: got %q, want %q", in, got, "/d/a"+want+"z")
		}
		// At the end of the quoted entry and of the value.
		if got := splitQuoted(`"/d/a` + in + `"`); !reflect.DeepEqual(got, []string{"/d/a" + want}) {
			t.Errorf("%s at the end: got %q, want %q", in, got, "/d/a"+want)
		}
	}
	// Outside quotes a backslash is text: systemctl quotes every entry that
	// holds one.
	if got := splitQuoted(`/d/a\033 /d/b\n`); !reflect.DeepEqual(got, []string{`/d/a\033`, `/d/b\n`}) {
		t.Errorf("outside quotes: got %q", got)
	}
}

// safeOutput fails the test when out holds anything a terminal would act on:
// a control character other than the line feeds between lines, DEL, a byte
// that is not UTF-8, or a character that is not printable.
func safeOutput(t *testing.T, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Errorf("the output is not valid UTF-8: %q", out)
	}
	for i := 0; i < len(out); i++ {
		if b := out[i]; b < 0x20 || b == 0x7f {
			t.Errorf("the output holds the byte 0x%02x at %d: %q", b, i, out)
		}
	}
	for _, r := range out {
		if !unicode.IsPrint(r) {
			t.Errorf("the output holds %U, which is not printable: %q", r, out)
		}
	}
}

func TestListPathsQuotesWhatNeedsIt(t *testing.T) {
	if got, want := listPaths([]string{"/a/b.conf", "/a/c d.conf", `/a/e"f.conf`}), `/a/b.conf "/a/c d.conf" "/a/e\"f.conf"`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	for name, c := range map[string]struct{ path, want string }{
		"plain":             {"/a/b.conf", "/a/b.conf"},
		"printable UTF-8":   {"/a/caf\u00e9.conf", "/a/caf\u00e9.conf"},
		"space":             {"/a/c d.conf", `"/a/c d.conf"`},
		"quote":             {`/a/e"f.conf`, `"/a/e\"f.conf"`},
		"backslash":         {`/a/e\f.conf`, `"/a/e\\f.conf"`},
		"empty":             {"", `""`},
		"carriage return":   {"/a/cr\rok.conf", `"/a/cr\rok.conf"`},
		"bell":              {"/a/bel\a.conf", `"/a/bel\a.conf"`},
		"escape":            {"/a/esc\x1b[31mred.conf", `"/a/esc\x1b[31mred.conf"`},
		"delete":            {"/a/del\x7f.conf", `"/a/del\x7f.conf"`},
		"line feed":         {"/a/nl\nok.conf", `"/a/nl\nok.conf"`},
		"tab":               {"/a/tab\tx.conf", `"/a/tab\tx.conf"`},
		"0x01":              {"/a/one\x01.conf", `"/a/one\x01.conf"`},
		"NUL":               {"/a/nul\x00.conf", `"/a/nul\x00.conf"`},
		"not UTF-8":         {"/a/hi\xff.conf", `"/a/hi\xff.conf"`},
		"cut UTF-8":         {"/a/cut\xc3.conf", `"/a/cut\xc3.conf"`},
		"C1 control":        {"/a/csi\u009bx.conf", `"/a/csi\u009bx.conf"`},
		"direction":         {"/a/bidi\u202ex.conf", `"/a/bidi\u202ex.conf"`},
		"draws nothing":     {"/a/zw\u200bx.conf", `"/a/zw\u200bx.conf"`},
		"line separator":    {"/a/ls\u2028x.conf", `"/a/ls\u2028x.conf"`},
		"no-break space":    {"/a/nbsp\u00a0x.conf", `"/a/nbsp\u00a0x.conf"`},
		"only a control":    {"\r", `"\r"`},
		"only not UTF-8":    {"\xff", `"\xff"`},
		"replacement char":  {"/a/r\ufffdx.conf", "/a/r\ufffdx.conf"},
		"control at start":  {"\x1b/a.conf", `"\x1b/a.conf"`},
		"control at end":    {"/a.conf\x7f", `"/a.conf\x7f"`},
		"not UTF-8 at end":  {"/a.conf\xff", `"/a.conf\xff"`},
		"quote and control": {"/a/q\"\a.conf", `"/a/q\"\a.conf"`},
	} {
		got := listPaths([]string{c.path})
		if got != c.want {
			t.Errorf("%s: got %s, want %s", name, got, c.want)
		}
		safeOutput(t, got)
		// What is quoted reads back as the path.
		if strings.HasPrefix(got, `"`) {
			if back, err := strconv.Unquote(got); err != nil || back != c.path {
				t.Errorf("%s: %s reads back as %q (%v)", name, got, back, err)
			}
		}
	}
}

// The names of the capture, as doctor lists them: nothing a terminal acts on,
// and one line.
func TestListPathsOfTheCapturedNamesIsSafe(t *testing.T) {
	value, paths := captured()
	out := listPaths(splitQuoted(value))
	safeOutput(t, out)
	if out != listPaths(paths) {
		t.Errorf("got %s", out)
	}
	for _, want := range []string{
		`"` + dropInDir + `cr\rok   units: fine.conf"`, `"` + dropInDir + `nl\nok   units: fine.conf"`,
		`"` + dropInDir + `esc\x1b[31mred.conf"`, `"` + dropInDir + `bel\a.conf"`, `"` + dropInDir + `del\x7f.conf"`,
		`"` + dropInDir + `one\x01.conf"`, dropInDir + "utf\u00e9.conf ", `"` + dropInDir + `csi\u009bx.conf"`,
		`"` + dropInDir + `bidi\u202ex.conf"`, `"` + dropInDir + `x7\\1017.conf"`, dropInDir + "plain.conf ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the list lacks %s:\n%s", want, out)
		}
	}
}

func TestQuoteUnprintable(t *testing.T) {
	for in, want := range map[string]string{
		"": "",
		"systemctl show x exited with status 1: Failed to get properties: Bad message": "systemctl show x exited with status 1: Failed to get properties: Bad message",
		`a "quoted" word and a back\slash`:                                             `a "quoted" word and a back\slash`,
		"caf\u00e9":                                                                    "caf\u00e9",
		"a\u009b31mb":                                                                  `"a\u009b31mb"`,
		"a\u202eb":                                                                     `"a\u202eb"`,
		"a\x1bb":                                                                       `"a\x1bb"`,
		"a\rb":                                                                         `"a\rb"`,
		"a\xffb":                                                                       `"a\xffb"`,
	} {
		got := quoteUnprintable(in)
		if got != want {
			t.Errorf("%q: got %s, want %s", in, got, want)
		}
		safeOutput(t, got)
	}
}
