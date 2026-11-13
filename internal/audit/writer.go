package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

var (
	// ErrFull is returned when a record would take the log past its size
	// limit, and by Open for a log that is already past it. The log is not
	// changed. Rotation does not exist; the daemon treats this as fatal.
	ErrFull = errors.New("audit log is at its size limit")
	// ErrCorrupt is returned by Open when the end of the log is damaged in a
	// way that is not a torn write: the last record decodes but its hash is
	// wrong, or the record before a torn line is not intact. Nothing is
	// appended; Verify names the place.
	ErrCorrupt = errors.New("audit log is damaged")
	// ErrClosed is returned by Append after Close.
	ErrClosed = errors.New("audit writer is closed")
)

// Options configures Open. The zero value is valid.
type Options struct {
	// MaxSize is the size in bytes at which the writer refuses to append.
	// Zero means DefaultMaxSize; a negative value is refused by Open.
	MaxSize int64
	// Now is the clock for the record Open appends after a torn tail. Nil
	// means time.Now.
	Now func() time.Time

	// syncFile replaces File.Sync in tests.
	syncFile func(*os.File) error
}

// Recovery describes the torn tail Open found and accounted for.
type Recovery struct {
	// Offset is where the torn line starts, Length how many bytes it has
	// (without a newline), Hash the hex SHA-256 of those bytes.
	Offset int64
	Length int64
	Hash   string
	// Completed is true when the last line was a whole, intact record that
	// only lacked its newline. It is then part of the chain (Open added the
	// newline) and not a torn line.
	Completed bool
	// Seq is the Seq of the audit_recovered record that was appended.
	Seq uint64
}

// Writer appends records to the audit log. It is safe for concurrent use
// within one process; it does not lock against another process, so the
// daemon's single-instance lock is what keeps a second writer out.
//
// Durability: every Append is one write of the whole line followed by an
// fsync of the file before it returns, so a record that Append reported is on
// disk, and a crash can leave at most one torn line, the one being written.
// The audit rate is low (one record per step of the daemon), so there is no
// batching.
//
// Failure: if a write or fsync fails, the Writer is unusable. Every later
// Append returns the first error. The file may then end in a torn line, which
// the next Open handles. ErrFull is not such a failure; the Writer stays
// usable (and stays full).
type Writer struct {
	mu     sync.Mutex
	f      *os.File
	max    int64
	size   int64
	seq    uint64
	prev   string
	sync   func(*os.File) error
	failed error
	closed bool
}

// Open opens (creating it if needed) the audit log in dir through
// securefile.OpenAppend, so the trust checks and the size check of that
// package apply. It reads the last complete record to continue Seq and Prev
// where the log ended; it does not verify the chain before it (that is
// Verify).
//
// A torn tail is the bytes after the last intact record: a last line without
// a newline, or a last line with a newline that is not a record (not JSON or
// not in canonical form). Open never rewrites or removes them. It ends the
// torn line with a newline if it lacks one and appends an audit_recovered
// record whose Summary names the line by offset, length and SHA-256. The
// returned Recovery is non-nil exactly in this case, so the caller can report
// it. Verify accepts such a line only because that record follows it.
//
// One variant: a last line without a newline that is a whole intact record
// (the write stopped one byte short) is not torn. Open adds the newline, the
// record stays in the chain, and an audit_recovered record notes that it was
// completed (Recovery.Completed).
//
// A last line that is a record with a wrong hash, or a torn line preceded by
// something that is not an intact record, is ErrCorrupt: that is not what an
// interrupted write looks like.
//
// The log is read into memory once, up to MaxSize, to find its end;
// securefile has no way to read just a tail yet.
func Open(dir *securefile.Dir, opts Options) (*Writer, *Recovery, error) {
	limit := opts.MaxSize
	if limit == 0 {
		limit = DefaultMaxSize
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	syncFn := opts.syncFile
	if syncFn == nil {
		syncFn = (*os.File).Sync
	}
	f, size, err := dir.OpenAppend(FileName, limit)
	if err != nil {
		if errors.Is(err, securefile.ErrTooLarge) {
			err = fmt.Errorf("%w: %w", ErrFull, err)
		}
		return nil, nil, err
	}
	w := &Writer{f: f, max: limit, size: size, prev: Genesis, sync: syncFn}
	t, err := w.resume(dir)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if t == nil {
		return w, nil, nil
	}
	// Terminate the torn line if needed and account for it.
	var prefix []byte
	if t.unterminated {
		prefix = []byte{'\n'}
	}
	summary := tornSummary(t.offset, t.length, t.sum)
	if t.completed {
		summary = completedSummary(t.offset, w.seq)
	}
	stamped, err := w.appendLocked(prefix, Record{Time: now(), Kind: AuditRecovered, Summary: summary})
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return w, &Recovery{Offset: t.offset, Length: t.length, Hash: t.sum, Completed: t.completed, Seq: stamped.Seq}, nil
}

// torn is the torn tail found by resume.
type torn struct {
	offset       int64
	length       int64
	sum          string
	unterminated bool
	// completed: the unterminated line is an intact record.
	completed bool
}

// resume sets seq and prev from the end of the log and returns the torn tail
// if there is one.
func (w *Writer) resume(dir *securefile.Dir) (*torn, error) {
	if w.size == 0 {
		return nil, nil
	}
	b, err := dir.ReadCapped(FileName, w.max)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != w.size {
		return nil, fmt.Errorf("%s was %d bytes when opened and %d bytes when read: %w", FileName, w.size, len(b), securefile.ErrChanged)
	}

	var t *torn
	// prevEnd is the index of the newline that ends the last intact line, or
	// -1 when there is no line before the torn one.
	var prevEnd int
	if lastNL := bytes.LastIndexByte(b, '\n'); lastNL != len(b)-1 {
		start := lastNL + 1
		t = &torn{offset: int64(start), length: int64(len(b) - start), unterminated: true}
		prevEnd = lastNL
		rec, lerr := decodeLine(b[start:])
		switch {
		case lerr == nil:
			t.completed = true
			t.sum = sumHex(b[start:])
			w.seq, w.prev = rec.Seq, rec.Hash
			return t, nil
		case lerr.reason != ReasonMalformed:
			return nil, fmt.Errorf("%w: last record (offset %d): %s", ErrCorrupt, start, lerr)
		}
	} else {
		start := bytes.LastIndexByte(b[:lastNL], '\n') + 1
		rec, lerr := decodeLine(b[start:lastNL])
		switch {
		case lerr == nil:
			w.seq, w.prev = rec.Seq, rec.Hash
			return nil, nil
		case lerr.reason != ReasonMalformed:
			return nil, fmt.Errorf("%w: last record (offset %d): %s", ErrCorrupt, start, lerr)
		}
		t = &torn{offset: int64(start), length: int64(lastNL - start)}
		prevEnd = start - 1
	}
	t.sum = sumHex(b[t.offset : t.offset+t.length])
	if prevEnd < 0 {
		return t, nil
	}
	start := bytes.LastIndexByte(b[:prevEnd], '\n') + 1
	rec, lerr := decodeLine(b[start:prevEnd])
	if lerr != nil {
		return nil, fmt.Errorf("%w: record before the torn line (offset %d): %s", ErrCorrupt, start, lerr)
	}
	w.seq, w.prev = rec.Seq, rec.Hash
	return t, nil
}

// Append stamps r with the next Seq, the Prev and the Hash, writes it and
// syncs the file, and returns the stored record. The Seq, Prev and Hash the
// caller sets are ignored. All strings are stored exactly as given, so the
// caller cleans them first (the audit log never sees raw journal or probe
// text); Append only refuses what it cannot store: a Summary over MaxSummary
// bytes (ErrSummaryTooLong, never cut), other fields over their limit
// (ErrFieldTooLong), and what ErrInvalidRecord names. A record that would
// take the log past its size limit gets ErrFull.
func (w *Writer) Append(r Record) (Record, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appendLocked(nil, r)
}

func (w *Writer) appendLocked(prefix []byte, r Record) (Record, error) {
	if w.closed {
		return Record{}, ErrClosed
	}
	if w.failed != nil {
		return Record{}, w.failed
	}
	if err := validate(r); err != nil {
		return Record{}, err
	}
	r.Seq = w.seq + 1
	r.Prev = w.prev
	r.Hash = hashOf(r)
	data := append(append([]byte(nil), prefix...), encodeLine(r)...)
	data = append(data, '\n')
	if w.size+int64(len(data)) > w.max {
		return Record{}, fmt.Errorf("%w: %d bytes in the log, %d more needed, limit %d", ErrFull, w.size, len(data), w.max)
	}
	// os.File.Write returns an error whenever it writes fewer bytes than given.
	_, err := w.f.Write(data)
	if err == nil {
		err = w.sync(w.f)
	}
	if err != nil {
		w.failed = fmt.Errorf("audit log write failed, writer is unusable: %w", err)
		return Record{}, w.failed
	}
	w.size += int64(len(data))
	w.seq, w.prev = r.Seq, r.Hash
	return r, nil
}

// Size is the size of the log in bytes as the writer knows it.
func (w *Writer) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}

// MaxSize is the size limit in force.
func (w *Writer) MaxSize() int64 { return w.max }

// Close closes the file. Later Appends return ErrClosed.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.f.Close()
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
