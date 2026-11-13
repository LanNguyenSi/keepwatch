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

// value is one journald field: a JSON string, a JSON array of byte values
// (journald's encoding of non-UTF-8 data), or null.
type value string

func (v *value) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return errors.New("empty value")
	}
	switch b[0] {
	case '"':
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*v = value(s)
	case '[':
		var raw []uint8
		if err := json.Unmarshal(b, &raw); err != nil {
			return fmt.Errorf("byte array: %w", err)
		}
		*v = value(raw)
	case 'n':
		*v = ""
	default:
		return errors.New("field is neither string, byte array nor null")
	}
	return nil
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

// Decode turns one journalctl JSON line into an Event. A line without
// __CURSOR is an error. A missing _UID or PRIORITY is -1, a missing _PID is 0.
func Decode(line []byte) (event.Event, error) {
	var e entry
	if err := json.Unmarshal(line, &e); err != nil {
		return event.Event{}, fmt.Errorf("journal: decode line: %w", err)
	}
	if e.Cursor == "" {
		return event.Event{}, errors.New("journal: line has no __CURSOR")
	}
	ev := event.Event{
		Kind:        event.KindJournal,
		Cursor:      string(e.Cursor),
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
			return event.Event{}, fmt.Errorf("journal: __REALTIME_TIMESTAMP: %w", err)
		}
		ev.Time = time.UnixMicro(us).UTC()
	}
	var err error
	if ev.PID, err = num("_PID", e.PID, 0); err != nil {
		return event.Event{}, err
	}
	if ev.UID, err = num("_UID", e.UID, -1); err != nil {
		return event.Event{}, err
	}
	if ev.Priority, err = num("PRIORITY", e.Priority, -1); err != nil {
		return event.Event{}, err
	}
	return ev, nil
}

func num(name string, v value, absent int) (int, error) {
	if v == "" {
		return absent, nil
	}
	n, err := strconv.Atoi(string(v))
	if err != nil {
		return 0, fmt.Errorf("journal: %s: %w", name, err)
	}
	return n, nil
}
