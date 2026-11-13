package journal

import (
	"errors"
	"strings"
)

// ErrBadCursor is returned by Args for a cursor that cannot be passed safely.
var ErrBadCursor = errors.New("journal: cursor contains a newline or NUL")

// Args returns the argv (without the program name) that follows the journal.
// With a cursor it resumes after that entry; without one it starts at now
// with no backlog. The cursor is one argv element and is never interpreted
// by a shell.
func Args(cursor string) ([]string, error) {
	args := []string{"--output=json", "--follow", "--no-pager"}
	if cursor == "" {
		return append(args, "--lines=0"), nil
	}
	if strings.ContainsAny(cursor, "\n\x00") {
		return nil, ErrBadCursor
	}
	return append(args, "--after-cursor="+cursor), nil
}
