// Package journal decodes `journalctl --output=json` lines into raw
// event.Event values and builds the journalctl argv.
//
// The decoder keeps raw text: it does not cut, escape or replace characters
// (see the event package for the trust and rawness rules).
package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

// LineError is returned by Decode for a line it cannot accept. Cursor is
// the line's __CURSOR when it could be read, so the caller can advance past
// the line; it is empty when the line is not JSON or has no cursor.
type LineError struct {
	Cursor string
	Err    error
}

func (e *LineError) Error() string { return "journal: " + e.Err.Error() }
func (e *LineError) Unwrap() error { return e.Err }

// value is one journald field as journalctl emits it: a JSON string, a JSON
// array of byte values (non-UTF-8 data), null (a field of 4096 bytes or more
// without --all), or an array of such values when the field occurs several
// times in the entry. The first value wins, as with sd_journal_get_data.
// Anything else decodes to empty: a sender can put odd data into its own
// fields, and that is data, not a decode failure.
type value string

func (v *value) UnmarshalJSON(b []byte) error {
	*v = value(firstValue(bytes.TrimSpace(b)))
	return nil
}

func firstValue(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case '"':
		return unquote(b)
	case '[':
		i := 1
		for i < len(b) && isSpace(b[i]) {
			i++
		}
		if i >= len(b) {
			return ""
		}
		switch {
		case b[i] == '"':
			return unquote(b[i:stringEnd(b, i)])
		case b[i] == '[':
			return byteArray(b[i:])
		case b[i] >= '0' && b[i] <= '9':
			return byteArray(b)
		}
	}
	return ""
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// stringEnd returns the index just after the string token that starts at i.
func stringEnd(b []byte, i int) int {
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1
		}
	}
	return len(b)
}

func unquote(tok []byte) string {
	var s string
	if err := json.Unmarshal(tok, &s); err != nil {
		return ""
	}
	return s
}

// byteArray reads the flat array of numbers that starts at b[0] and returns
// its bytes. The buffer is sized from the element count, so decoding
// allocates about the size of the array's text at most. A malformed array
// or a number above 255 gives empty.
func byteArray(b []byte) string {
	end := bytes.IndexByte(b, ']')
	if end < 0 {
		return ""
	}
	out := make([]byte, 0, bytes.Count(b[:end], []byte{','})+1)
	i := 1
	for {
		for i < len(b) && isSpace(b[i]) {
			i++
		}
		n, digits := 0, 0
		for i < len(b) && b[i] >= '0' && b[i] <= '9' && digits < 4 {
			n = n*10 + int(b[i]-'0')
			i++
			digits++
		}
		if digits == 0 || n > 255 {
			return ""
		}
		out = append(out, byte(n))
		for i < len(b) && isSpace(b[i]) {
			i++
		}
		if i >= len(b) {
			return ""
		}
		switch b[i] {
		case ',':
			i++
		case ']':
			return string(out)
		default:
			return ""
		}
	}
}

// entry lists the whitelisted fields. encoding/json skips every other key
// without keeping it.
type entry struct {
	Cursor     value `json:"__CURSOR"`
	Realtime   value `json:"__REALTIME_TIMESTAMP"`
	Message    value `json:"MESSAGE"`
	SystemdU   value `json:"_SYSTEMD_UNIT"`
	Unit       value `json:"UNIT"`
	Identifier value `json:"SYSLOG_IDENTIFIER"`
	PID        value `json:"_PID"`
	UID        value `json:"_UID"`
	Priority   value `json:"PRIORITY"`
	Transport  value `json:"_TRANSPORT"`
	Comm       value `json:"_COMM"`
	UnitResult value `json:"UNIT_RESULT"`
	ExitCode   value `json:"EXIT_CODE"`
	ExitStatus value `json:"EXIT_STATUS"`
}

// Decode turns one journalctl JSON line into an Event. Every error is a
// *LineError. A line without __CURSOR is an error, and so is a bad _PID,
// _UID or __REALTIME_TIMESTAMP (journald-set fields). Problems in
// sender-set fields are data: a field with several values yields the first,
// and a PRIORITY that is not a number or lies outside 0..7 becomes -1, like
// an absent one. A missing _UID is -1, a missing _PID is 0, and a missing
// __REALTIME_TIMESTAMP leaves Time zero.
//
// With the arguments from Args, journalctl emits a field of 4096 bytes or
// more as null, so a large MESSAGE reaches Decode as an empty Message.
func Decode(line []byte) (event.Event, error) {
	var e entry
	if err := json.Unmarshal(line, &e); err != nil {
		return event.Event{}, &LineError{Err: fmt.Errorf("decode line: %w", err)}
	}
	if e.Cursor == "" {
		return event.Event{}, &LineError{Err: errors.New("line has no __CURSOR")}
	}
	cur := string(e.Cursor)
	fail := func(err error) (event.Event, error) {
		return event.Event{}, &LineError{Cursor: cur, Err: err}
	}
	ev := event.Event{
		Kind:        event.KindJournal,
		Cursor:      cur,
		SystemdUnit: string(e.SystemdU),
		Unit:        string(e.Unit),
		Identifier:  string(e.Identifier),
		Transport:   string(e.Transport),
		Message:     string(e.Message),
		Comm:        string(e.Comm),
		UnitResult:  string(e.UnitResult),
		ExitCode:    string(e.ExitCode),
		ExitStatus:  string(e.ExitStatus),
	}
	if e.Realtime != "" {
		us, err := strconv.ParseInt(string(e.Realtime), 10, 64)
		if err != nil {
			return fail(fmt.Errorf("__REALTIME_TIMESTAMP: %w", err))
		}
		ev.Time = time.UnixMicro(us).UTC()
	}
	var err error
	if ev.PID, err = num("_PID", e.PID, 0); err != nil {
		return fail(err)
	}
	if ev.UID, err = num("_UID", e.UID, -1); err != nil {
		return fail(err)
	}
	ev.Priority = -1
	if p, perr := strconv.Atoi(string(e.Priority)); perr == nil && p >= 0 && p <= 7 {
		ev.Priority = p
	}
	return ev, nil
}

func num(name string, v value, absent int) (int, error) {
	if v == "" {
		return absent, nil
	}
	n, err := strconv.Atoi(string(v))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return n, nil
}
