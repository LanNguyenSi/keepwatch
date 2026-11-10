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

		// Characters that draw nothing, or draw what the reader's font says.
		{"hangul choseong filler\u115fx", `hangul choseong filler\u115fx`},
		{"hangul jungseong filler\u1160x", `hangul jungseong filler\u1160x`},
		{"hangul filler\u3164x", `hangul filler\u3164x`},
		{"halfwidth hangul filler\uffa0x", `halfwidth hangul filler\uffa0x`},
		{"grapheme joiner a\u034fb", `grapheme joiner a\u034fb`},
		{"khmer inherent vowels\u17b4\u17b5x", `khmer inherent vowels\u17b4\u17b5x`},
		{"braille blank\u2800x", `braille blank\u2800x`},
		{"vs1 \ufe00 vs16 \ufe0f", `vs1 \ufe00 vs16 \ufe0f`},
		{"vs17 \U000e0100 vs256 \U000e01ef", `vs17 \U000e0100 vs256 \U000e01ef`},
		{"mongolian vs \u180b\u180c\u180d\u180f", `mongolian vs \u180b\u180c\u180d\u180f`},
		{"private use \ue000 \uf8ff", `private use \ue000 \uf8ff`},
		{"private use plane 15 \U000f0000", `private use plane 15 \U000f0000`},
		{"private use plane 16 \U0010fffd", `private use plane 16 \U0010fffd`},
		{"unassigned \u0378", `unassigned \u0378`},
		{"noncharacter \uffff \ufdd0", `noncharacter \uffff \ufdd0`},
		{"noncharacter \U0010ffff", `noncharacter \U0010ffff`},
		{"unassigned plane 4 \U00040000", `unassigned plane 4 \U00040000`},
		// What stays: letters, marks, spaces, symbols and emoji.
		{"e\u0301 combining acute", "e\u0301 combining acute"},
		{"ideographic\u3000space", "ideographic\u3000space"},
		{"emoji \U0001f642", "emoji \U0001f642"},
		{"zalgo a\u0300\u0301\u0302", "zalgo a\u0300\u0301\u0302"},
		{"hangul 한국어", "hangul 한국어"},
		{"khmer \u1780\u17b6", "khmer \u1780\u17b6"},
		{"braille \u2801\u283f", "braille \u2801\u283f"},
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

// Every code point that is not a printable character is escaped. The sweep is
// over the whole code space, so a character that a new Unicode version adds
// to a dangerous category cannot slip past without being noticed.
func TestEscapeSweepOverAllCodePoints(t *testing.T) {
	printable := func(r rune) bool {
		return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Zs)
	}
	var escaped, kept int
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		if r >= 0xd800 && r <= 0xdfff {
			continue // surrogates cannot be encoded
		}
		s := string(r)
		got := Escape(s)
		if got == s {
			kept++
			if !printable(r) {
				t.Errorf("U+%04X (%q) is not escaped and is not printable", r, s)
			}
			if invisible(r) {
				t.Errorf("U+%04X is invisible and not escaped", r)
			}
		} else {
			escaped++
			if !strings.HasPrefix(got, `\u`) && !strings.HasPrefix(got, `\U`) {
				t.Errorf("U+%04X escaped as %q", r, got)
			}
		}
	}
	if escaped < 1000 || kept < 100000 {
		t.Errorf("escaped %d, kept %d code points: the sweep looks wrong", escaped, kept)
	}
}

func TestEscapeIsIdempotentOnItsOutput(t *testing.T) {
	in := "a\x1b[31m\n\u202e\xff"
	once := Escape(in)
	if Escape(once) != once {
		t.Errorf("not idempotent: %q", once)
	}
}
