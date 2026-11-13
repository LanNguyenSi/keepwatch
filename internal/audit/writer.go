package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

var (
	// ErrFull is returned when a record would take the log past the size it
	// is allowed to reach (see ReserveBytes), and by Open for a log that is
	// already past MaxSize. The log is not changed. Rotation does not exist;
	// the daemon treats this as fatal. What an operator does with a full log
	// is in the package documentation.
	ErrFull = errors.New("audit log is at its size limit")
	// ErrCorrupt is returned by Open when the end of the log is damaged in a
	// way that is not a torn write: a record after the last intact one has a
	// wrong hash, the bytes after the last intact record are more than
	// MaxTornBytes, or there is no intact record in the window Open reads.
	// Nothing is appended; Verify names the place.
	ErrCorrupt = errors.New("audit log is damaged")
	// ErrClosed is returned by Append after Close.
	ErrClosed = errors.New("audit writer is closed")
)

// Options configures Open. The zero value is valid.
type Options struct {
	// MaxSize is the size in bytes of the file the writer never exceeds.
	// Ordinary records stop at MaxSize-ReserveBytes. Zero means
	// DefaultMaxSize; a negative value is refused by Open.
	MaxSize int64
	// Now is the clock for the record Open appends after a torn tail. Nil
	// means time.Now.
	Now func() time.Time

	// syncFile replaces File.Sync in tests.
	syncFile func(*os.File) error
	// afterOpen runs between the open of the file and the read of its end,
	// in tests.
	afterOpen func()
}

// Recovery describes the torn tail Open found and accounted for.
type Recovery struct {
	// Offset is where the torn region starts and Length how many bytes it
	// has (the bytes after the last intact record, newlines inside included;
	// a newline Open added to end it is not counted). Hash is the hex
	// SHA-256 of those bytes.
	Offset int64
	Length int64
	Hash   string
	// Terminated is true when the region already ended with a newline. When
	// it is false Open added one, which says more than the region itself: a
	// crash in the middle of a write leaves no newline, a region that ends
	// in a newline was written by someone who finished a line. The caller
	// should report every Recovery as security relevant: the bytes may hold
	// a record that was erased, and the Seq of the erased record is reused.
	Terminated bool
	// Completed is true when the last line was a whole, intact record that
	// only lacked its newline. It is then part of the chain (Open added the
	// newline) and not a torn region; Terminated is false.
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
// Size: ordinary records are refused with ErrFull once the file would pass
// MaxSize-ReserveBytes. The reserve is for the last words: one terminal
// record (kind DaemonError or DaemonStop) and the audit_recovered record
// that Open appends may use it, up to MaxSize. A second terminal record is
// an ordinary one. Nothing ever shrinks or rotates the file.
//
// Failure: if a write or fsync fails, the Writer is unusable. Every later
// Append returns the first error. The file may then end in a torn line, which
// the next Open handles. ErrFull is not such a failure; the Writer stays
// usable (and stays full).
type Writer struct {
	mu       sync.Mutex
	f        *os.File
	max      int64
	size     int64
	seq      uint64
	prev     string
	sync     func(*os.File) error
	failed   error
	closed   bool
	terminal bool

	// afterStat runs between the size check and the read of resume, in
	// tests.
	afterStat func()
}

// Open opens (creating it if needed) the audit log in dir through
// securefile.OpenAppendReadable, so the trust checks and the size check of
// that package apply, and reads the end of the very file it will append to:
// a fixed window from the end, never the whole log, and no second open by
// name. It finds the last intact record to continue Seq and Prev where the
// log ended; it does not verify the chain before it (that is Verify). What
// counts as an intact record is what decodeLine accepts, the same lines that
// Verify accepts as records: a line longer than MaxLineBytes is never one,
// because no record Append can store has such a line.
//
// A torn tail is all the bytes after the last intact record: a last line
// without a newline, lines that are not records (not JSON or not in
// canonical form), several of them, newlines among them. That is what a
// crash leaves, also a crash in the middle of this recovery. Open never
// rewrites or removes those bytes. It ends the region with a newline if it
// lacks one and appends an audit_recovered record whose Summary names the
// region by offset, length, whether it ended with a newline, and SHA-256.
// The returned Recovery is non-nil exactly in this case, so the caller can
// report it. Verify accepts the region only because that record follows it.
// If Open is interrupted while it writes that record, the next Open finds
// the region with the partial record at its end and accounts for all of it
// again.
//
// One variant: a last line without a newline that is a whole intact record
// (the write stopped one byte short) is not torn. Open adds the newline, the
// record stays in the chain, and an audit_recovered record notes that it was
// completed (Recovery.Completed).
//
// ErrCorrupt: a line after the last intact record that looks like a record
// but has a wrong hash (that is not what an interrupted write looks like), or
// more than MaxTornBytes after the last intact record (which includes a log
// longer than the window that has no intact record in it). The recovery
// record may use the reserve (ReserveBytes); if even that is not enough, Open
// returns ErrFull.
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
	f, size, err := dir.OpenAppendReadable(FileName, limit)
	if err != nil {
		if errors.Is(err, securefile.ErrTooLarge) {
			err = fmt.Errorf("%w: %w", ErrFull, err)
		}
		return nil, nil, err
	}
	w := &Writer{f: f, max: limit, size: size, prev: Genesis, sync: syncFn}
	if opts.afterOpen != nil {
		opts.afterOpen()
	}
	t, err := w.resume()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if t == nil {
		return w, nil, nil
	}
	// Terminate the torn region if needed and account for it.
	var prefix []byte
	if !t.terminated {
		prefix = []byte{'\n'}
	}
	summary := tornSummary(t.offset, t.length, t.terminated, t.sum)
	if t.completed {
		summary = completedSummary(t.offset, w.seq)
	}
	stamped, err := w.appendLocked(prefix, Record{Time: now(), Kind: AuditRecovered, Summary: summary}, true)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return w, &Recovery{Offset: t.offset, Length: t.length, Hash: t.sum, Terminated: t.terminated,
		Completed: t.completed, Seq: stamped.Seq}, nil
}

// torn is the torn tail found by resume.
type torn struct {
	offset int64
	length int64
	sum    string
	// terminated: the region ends with a newline.
	terminated bool
	// completed: the unterminated last line is an intact record.
	completed bool
}

// resume sets seq and prev from the end of the log and returns the torn tail
// if there is one. It reads a window of at most tailWindow bytes from the end
// of the file it holds open, with ReadAt.
func (w *Writer) resume() (*torn, error) {
	if fi, err := w.f.Stat(); err != nil {
		return nil, err
	} else if fi.Size() != w.size {
		return nil, fmt.Errorf("%s was %d bytes when opened and %d bytes when read: %w", FileName, w.size, fi.Size(), securefile.ErrChanged)
	}
	if w.afterStat != nil {
		w.afterStat()
	}
	// The window may start in the middle of a line. That first line is then
	// cut and so not a record, which is all that is needed of it.
	base := max(0, w.size-tailWindow)
	data := make([]byte, w.size-base)
	if _, err := w.f.ReadAt(data, base); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s ended before %d bytes when read: %w", FileName, w.size, securefile.ErrChanged)
		}
		return nil, err
	}

	// Walk the lines of the window. regionAt is where the bytes after the
	// last intact record start; badAt is the start of a line after the last
	// intact record that looks like a record but has a wrong hash (-1 for
	// none).
	var last Record
	haveIntact, completed := false, false
	lastStart, regionAt, badAt := 0, 0, -1
	for pos := 0; pos < len(data); {
		end := len(data)
		if nl := bytes.IndexByte(data[pos:], '\n'); nl >= 0 {
			end = pos + nl
		}
		rec, lerr := decodeLine(data[pos:end])
		switch {
		case lerr == nil:
			last, haveIntact = rec, true
			badAt = -1
			lastStart = pos
			completed = end == len(data)
			regionAt = end + 1
		case lerr.reason != ReasonMalformed:
			badAt = pos
		}
		pos = end + 1
	}
	if badAt >= 0 {
		return nil, fmt.Errorf("%w: the line at offset %d has a wrong hash and follows the last intact record", ErrCorrupt, base+int64(badAt))
	}
	if haveIntact {
		w.seq, w.prev = last.Seq, last.Hash
	}
	if completed {
		line := data[lastStart:]
		return &torn{offset: base + int64(lastStart), length: int64(len(line)), sum: sumHex(line), completed: true}, nil
	}
	region := data[regionAt:]
	if len(region) == 0 {
		return nil, nil
	}
	if len(region) > MaxTornBytes {
		return nil, fmt.Errorf("%w: %d bytes after the last intact record, limit %d", ErrCorrupt, len(region), MaxTornBytes)
	}
	return &torn{offset: base + int64(regionAt), length: int64(len(region)), sum: sumHex(region),
		terminated: region[len(region)-1] == '\n'}, nil
}

// Append stamps r with the next Seq, the Prev and the Hash, writes it and
// syncs the file, and returns the stored record. The Seq, Prev and Hash the
// caller sets are ignored. All strings are stored exactly as given, so the
// caller cleans them first (the audit log never sees raw journal or probe
// text); Append only refuses what it cannot store: a Summary over MaxSummary
// bytes (ErrSummaryTooLong, never cut), other fields over their limit
// (ErrFieldTooLong), and what ErrInvalidRecord names. A record that would
// take the log past MaxSize-ReserveBytes gets ErrFull, except the first
// record of kind DaemonError or DaemonStop, which may use the reserve up to
// MaxSize.
func (w *Writer) Append(r Record) (Record, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	terminal := (r.Kind == DaemonError || r.Kind == DaemonStop) && !w.terminal
	got, err := w.appendLocked(nil, r, terminal)
	if err == nil && terminal {
		w.terminal = true
	}
	return got, err
}

// appendLocked writes prefix and r. useReserve lets the write take the room
// that ordinary records may not.
func (w *Writer) appendLocked(prefix []byte, r Record, useReserve bool) (Record, error) {
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
	limit := w.max - ReserveBytes
	if useReserve {
		limit = w.max
	}
	if w.size+int64(len(data)) > limit {
		return Record{}, fmt.Errorf("%w: %d bytes in the log, %d more needed, limit %d (size limit %d, reserve %d)", ErrFull, w.size, len(data), limit, w.max, ReserveBytes)
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
