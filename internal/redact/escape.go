package redact

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escape returns s with every character that is not safe to print replaced
// by a visible escape sequence, so the result is one line of printable
// UTF-8:
//
//   - the C0 controls and DEL: \n, \r and \t for those three, \xNN for the
//     rest (this covers ESC, so a terminal escape sequence loses its effect
//     and stays readable as text);
//   - the C1 controls (U+0080 to U+009F), including the 8-bit CSI: \u0085;
//   - the Unicode format characters, which include the bidirectional
//     overrides and isolates, the zero-width characters and the byte order
//     mark, and the line and paragraph separators: \uNNNN or \UNNNNNNNN;
//   - characters that draw nothing but are not format characters, which
//     could make two different names look alike: the fillers (U+115F,
//     U+1160, U+3164, U+FFA0, U+17B4, U+17B5, U+2800), the combining
//     grapheme joiner (U+034F) and the variation selectors (U+180B to
//     U+180D, U+180F, U+FE00 to U+FE0F, U+E0100 to U+E01EF);
//   - private-use characters and code points that are unassigned (or
//     noncharacters): what they show depends on the font of whoever reads
//     the report;
//   - bytes that are not valid UTF-8: \xNN.
//
// Other characters, including all printable non-ASCII text, are kept. A
// backslash is kept too, so the escapes are for the eye of an operator, not
// a reversible encoding; code that must tell two subjects apart compares the
// raw text, never the escaped one.
func Escape(s string) string {
	if !needsEscape(s) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&sb, `\x%02x`, s[i])
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&sb, `\x%02x`, r)
		case unsafeRune(r):
			if r > 0xffff {
				fmt.Fprintf(&sb, `\U%08x`, r)
			} else {
				fmt.Fprintf(&sb, `\u%04x`, r)
			}
		default:
			sb.WriteString(s[i : i+size])
		}
		i += size
	}
	return sb.String()
}

// unsafeRune reports whether a rune of 0x80 or above must be escaped. Go's
// category C is every "other" code point: controls, format characters,
// private use, surrogates and the unassigned ones.
func unsafeRune(r rune) bool {
	return unicode.In(r, unicode.C, unicode.Zl, unicode.Zp) || invisible(r)
}

// invisible reports whether r is a character that draws nothing and is not
// one of the format characters.
func invisible(r rune) bool {
	switch r {
	case 0x034f, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180b, 0x180c, 0x180d, 0x180f, 0x2800, 0x3164, 0xffa0:
		return true
	}
	return (r >= 0xfe00 && r <= 0xfe0f) || (r >= 0xe0100 && r <= 0xe01ef)
}

func needsEscape(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || r < 0x20 || r == 0x7f || (r >= 0x80 && unsafeRune(r)) {
			return true
		}
		i += size
	}
	return false
}
