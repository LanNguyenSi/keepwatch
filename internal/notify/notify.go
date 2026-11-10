// Package notify delivers a keepwatch message to a notification channel.
//
// Stage 0 has one channel, ntfy (Ntfy). The package knows nothing about
// reports, checks or state: it is handed a finished Message and either
// delivers it or says why it could not. What goes into a message, and its
// redaction, is decided by the caller (the render package builds the text,
// every string of it passes through the redactor before it gets here).
//
// Delivery is at least once. A delivery that failed on the network may have
// reached the server anyway (the answer got lost), so a retry, and the next
// run after a failure, can show the same message twice; the caller keeps the
// state of the last run where it was until a delivery succeeded, so a change
// is never lost, at worst told twice.
package notify

import (
	"context"
	"errors"
	"fmt"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// Message is what is sent.
type Message struct {
	// Title is one line; characters outside printable ASCII are replaced by
	// '?' because it travels in an HTTP header.
	Title string
	// Body is the text of the notification, at most MaxBodyBytes bytes.
	Body string
	// Markdown asks the channel to render Body as Markdown.
	Markdown bool
	// Priority is 1 (lowest) to 5 (highest); 0 means the channel default.
	Priority int
	// Tags are short words from [A-Za-z0-9_+-]; the channel shows a tag that
	// names an emoji as that emoji.
	Tags []string
}

// Notifier delivers messages.
type Notifier interface {
	// Send delivers m. The error is an *Error.
	Send(ctx context.Context, m Message) error
}

// Limits of a message.
const (
	// MaxBodyBytes is the largest body Send accepts. ntfy's default message
	// size limit is 4096 bytes; a longer body would be turned into an
	// attachment or cut by the server, neither of which a Markdown message
	// survives, so keepwatch builds bodies that fit and Send refuses others.
	MaxBodyBytes = 4096
	// MaxTitleBytes bounds the Title header.
	MaxTitleBytes = 250
	maxTags       = 5
)

// Class says whether trying again can help.
type Class int

// The classes of a failure.
const (
	// Permanent: the same request would fail again (a refused credential, an
	// unknown topic, a redirect, a message that is too large, a bad setting).
	Permanent Class = iota
	// Transient: the server or the network failed (5xx, 429, no answer).
	Transient
)

func (c Class) String() string {
	if c == Transient {
		return "transient"
	}
	return "permanent"
}

// Error is a failed delivery. Its text never holds the address of the server
// (the topic is a secret on an open server), the token or the message.
type Error struct {
	Class Class
	// Status is the HTTP status, 0 when there was no answer.
	Status int
	// Attempts is how many requests were made (0 when none was).
	Attempts int
	// Msg says what went wrong, in a few words.
	Msg string
}

func (e *Error) Error() string {
	s := "ntfy: " + e.Msg
	if e.Attempts > 1 {
		s += fmt.Sprintf(" (after %d attempts)", e.Attempts)
	}
	return s
}

// AsError returns err as an *Error, or nil.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// PriorityOf maps a severity to a message priority: critical is 5 (urgent),
// high 4, medium 3 (the channel default), low 2 and info 1. An unknown
// severity gets the default.
func PriorityOf(s result.Severity) int {
	switch s {
	case result.Critical:
		return 5
	case result.High:
		return 4
	case result.Medium:
		return 3
	case result.Low:
		return 2
	case result.Info:
		return 1
	}
	return 3
}
