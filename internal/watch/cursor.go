package watch

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"

	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

// CursorFile is the name of the cursor file inside the state directory.
const CursorFile = "cursor"

// MaxCursorBytes bounds the cursor file. A journald cursor is about a hundred
// characters; the bound only keeps a hostile file from being read whole.
const MaxCursorBytes = 1024

// ErrInvalidCursor is returned by Load for a cursor file whose content cannot
// be a journald cursor (too long, or characters outside printable ASCII). The
// daemon treats it as a lost cursor, not as a failure of the state directory.
var ErrInvalidCursor = errors.New("watch: the cursor file does not hold a journal cursor")

// CursorStore keeps the journal cursor of the last fully handled line in
// CursorFile. The daemon is the only writer.
type CursorStore struct{ dir *securefile.Dir }

// NewCursorStore returns a store over the state directory.
func NewCursorStore(dir *securefile.Dir) *CursorStore { return &CursorStore{dir: dir} }

// validCursor reports whether s may be passed to journalctl as one argument:
// printable ASCII without space, at most MaxCursorBytes-1 bytes. The empty
// string is valid and means "no cursor".
func validCursor(s string) bool {
	if len(s) >= MaxCursorBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// Load returns the saved cursor, or "" when there is none (no file, or an
// empty one). A file that is too large or holds other than a cursor is
// ErrInvalidCursor; a file that fails the trust checks, and any other read
// error, is returned as it is.
func (c *CursorStore) Load() (string, error) {
	b, err := c.dir.ReadCapped(CursorFile, MaxCursorBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", nil
	case errors.Is(err, securefile.ErrTooLarge):
		return "", fmt.Errorf("%w: %v", ErrInvalidCursor, err)
	case err != nil:
		return "", err
	}
	s := string(bytes.TrimSuffix(b, []byte("\n")))
	if !validCursor(s) {
		return "", ErrInvalidCursor
	}
	return s, nil
}

// Save writes cur atomically; "" clears the cursor. The write is durable
// when Save returns.
func (c *CursorStore) Save(cur string) error {
	if !validCursor(cur) {
		return fmt.Errorf("%w: refusing to save it", ErrInvalidCursor)
	}
	return c.dir.WriteAtomic(CursorFile, []byte(cur+"\n"), MaxCursorBytes)
}
