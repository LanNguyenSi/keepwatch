package redact

import (
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func mustCompile(t *testing.T, p string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return re
}

func TestEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain text", "plain text"},
		{"", ""},
		{"héllo 日本語 ✓", "héllo 日本語 ✓"},
		{"back\\slash", "back\\slash"},
		{"a\nb", `a\nb`},
		{"a\r\nb", `a\r\nb`},
		{"a\tb", `a\tb`},
		{"\x00", `\x00`},
		{"\x07bell", `\x07bell`},
		{"\x08back", `\x08back`},
		{"\x1b[31mred\x1b[0m", `\x1b[31mred\x1b[0m`},
		{"\x1b]0;title\x07", `\x1b]0;title\x07`},
		{"\x1b]8;;http://evil\x07link\x1b]8;;\x07", `\x1b]8;;http://evil\x07link\x1b]8;;\x07`},
		{"del\x7f", `del\x7f`},
		{"c1\u0085next", `c1\u0085next`},
		{"csi\u009b31m", `csi\u009b31m`},
		{"\u009d0;t\u009c", `\u009d0;t\u009c`},
		{"rtl\u202eevil", `rtl\u202eevil`},
		{"iso\u2066x\u2069", `iso\u2066x\u2069`},
		{"zw\u200bsp", `zw\u200bsp`},
		{"bom\ufeffx", `bom\ufeffx`},
		{"soft\u00adhyphen", `soft\u00adhyphen`},
		{"sep\u2028line\u2029para", `sep\u2028line\u2029para`},
		{"tag\U000e0041x", `tag\U000e0041x`},
		{"bad\xffbyte", `bad\xffbyte`},
		{"trunc\xe2\x82", `trunc\xe2\x82`},
		{"overlong\xc0\xaf", `overlong\xc0\xaf`},
		{"lit\ufffdrepl", "lit\ufffdrepl"},
		{"nbsp\u00a0ok", "nbsp\u00a0ok"},
		{"lit\ufffd and \x00", "lit\ufffd and \\x00"},
	}
	for _, c := range cases {
		if got := Escape(c.in); got != c.want {
			t.Errorf("Escape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEscapeOutputIsAlwaysSafe(t *testing.T) {
	var all strings.Builder
	for r := rune(0); r < 0x3000; r++ {
		all.WriteRune(r)
	}
	for _, r := range []rune{0xe0001, 0xe0020, 0x1d173, 0x10ffff, 0xfff9, 0xfffb} {
		all.WriteRune(r)
	}
	for b := 0; b < 256; b++ {
		all.WriteByte(byte(b))
	}
	got := Escape(all.String())
	if !utf8.ValidString(got) {
		t.Fatal("output is not valid UTF-8")
	}
	for _, r := range got {
		if r < 0x20 || r == 0x7f || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			t.Fatalf("output holds U+%04X", r)
		}
	}
}

func TestEscapeIsIdempotentOnItsOutput(t *testing.T) {
	in := "a\x1b[31m\n\u202e\xff"
	once := Escape(in)
	if Escape(once) != once {
		t.Errorf("not idempotent: %q", once)
	}
}
