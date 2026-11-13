// Package requests is the spool through which the command line asks the watch
// daemon to acknowledge or close an incident.
//
// The daemon is the only writer of the incident store, the audit log and the
// cursor. A command that wants an incident acked or closed therefore does not
// touch those files: Submit drops one small request file into the
// "requests" subdirectory of the state directory, and the daemon reads the
// pending files with Pending, applies and audits each one, and deletes it with
// Remove. Nothing in this package reads or writes the incident store or the
// audit log.
//
// Everything in a request file is untrusted input, even when the file passes
// the owner and mode checks: the checks say who can have written it, not that
// the content is sane. Note in particular is raw text chosen by whoever wrote
// the file (it may hold control characters, escape sequences or secrets). The
// daemon cleans it before it reaches the audit log or any output; this
// package neither cleans nor interprets it. RequestedAt is a claim of the
// writer, not the time the daemon saw the file.
//
// # Trust rules
//
// The state directory and the requests directory must be real directories
// (not symlinks) owned by uid 0 or the running user and not writable by group
// or other; Submit creates the requests directory with mode 0700. A request
// file must be a regular file (not a symlink) owned by uid 0 or the running
// user, with no permission bit beyond 0600 (so no group or other read or
// write, and no setuid, setgid or sticky bit), at most MaxFileSize bytes, and
// named as Submit names it. A file that fails a rule is not an error of
// Pending: it is returned as a rejected Item with a Reason, so the daemon can
// audit it and Remove it instead of seeing it again on every pass. Permissions
// are mode bits and owner only (ACLs and capabilities are not examined, the
// known limit of the securefile package).
//
// The strict "no bit beyond 0600" rule is a first-look check on the entry as
// listed: a file swapped in between that look and the open is not held to it.
// What the open enforces (through securefile) is the type (regular file), the
// owner (uid 0 or the running user) and that group and other cannot write; the
// size is capped again while reading. The content is untrusted anyway, so a
// swapped-in file gains nothing beyond what its owner could have written.
//
// # Delivery
//
// Pending does not remove anything. The daemon decides the order of apply,
// audit and Remove, and with it whether a crash in between replays a request
// (remove after apply: at least once) or drops it (remove before apply: at
// most once). A rejected or consumed file that Remove cannot delete shows up
// again on the next Pending call; Remove deletes any entry of the directory,
// including a directory with content, so only an entry the daemon is not
// allowed to delete (a foreign-owned one in a directory the daemon does not
// own) stays.
//
// # Bounds
//
// One Pending call looks at no more than MaxPending files, in name order, so
// a flood of files costs the daemon a bounded amount of work per pass. Only
// entries named as Submit names them count toward that window (Batch.Items).
// Everything else in the directory (a stray file, a directory, a name with a
// backslash) is reported in a separate list, Batch.Stray, capped at MaxStray
// and never opened, so junk that sorts before the real requests cannot starve
// them. The names of the directory are read in chunks, and at most
// MaxExamined entries are examined per call; when the directory holds more,
// Batch.Overfull is set (the daemon should alert: someone is filling the
// directory, and entries beyond the examined ones are not seen until the rest
// is removed). Names start with the submission time in nanoseconds, so name
// order is submission order for requests from one machine; the rest of the
// name is 128 random bits, which makes it unpredictable.
//
// # Leftovers
//
// A Submit that is killed between creating its temporary file and renaming it
// leaves a file named with securefile.TempPrefix. Pending ignores such files
// and Remove refuses them, since they may belong to a write in progress;
// SweepTemp removes the ones older than a given age.
package requests

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

// DirName is the name of the requests directory inside the state directory.
const DirName = "requests"

// SchemaVersion is the schema_version of a request file written by this
// version of the package. A file with another version is rejected.
const SchemaVersion = 1

const (
	// MaxFileSize is the largest request file, in bytes. A larger file is
	// rejected without being read.
	MaxFileSize = 16 * 1024
	// MaxNoteBytes is the longest Note Submit accepts, in bytes. Pending
	// rejects a file whose note is longer.
	MaxNoteBytes = 1024
	// MaxIncidentIDBytes is the longest incident ID accepted (the incident
	// store's own limit).
	MaxIncidentIDBytes = 80
	// MaxPending is the largest number of files named as Submit names them
	// that one Pending call opens and returns. Rejected files of that name
	// count; temporary files and entries of another name do not.
	MaxPending = 100
	// MaxStray is the largest number of entries of another name that one
	// Pending call reports (in Batch.Stray). They are not opened.
	MaxStray = 20
	// MaxExamined is the largest number of directory entries one Pending call
	// (or SweepTemp call) examines; temporary files count.
	MaxExamined = 10000
)

// Action is what a request asks for.
type Action string

const (
	ActionAck   Action = "ack"
	ActionClose Action = "close"
)

// Valid reports whether a is a known action.
func (a Action) Valid() bool { return a == ActionAck || a == ActionClose }

// Request is one ack or close request. Every field read from a file is
// untrusted, Note most of all: it is raw text (see the package comment).
type Request struct {
	Action     Action
	IncidentID string
	// Note is raw, uncleaned text of at most MaxNoteBytes bytes.
	Note string
	// RequestedAt is the time the writer claims. Submit fills it with the
	// current time when it is zero.
	RequestedAt time.Time
}

// ErrInvalidRequest is returned by Submit for a request that Pending would
// reject.
var ErrInvalidRequest = errors.New("invalid request")

// ValidIncidentID reports whether id has the shape of an incident ID: 1 to
// MaxIncidentIDBytes bytes, the first a lowercase hex digit and the rest
// lowercase hex digits or "-" (the store makes 8 to 64 hex digits, and a
// numbered suffix "-N" on a collision). It checks the shape only; whether the
// incident exists is for the daemon.
func ValidIncidentID(id string) bool {
	if id == "" || len(id) > MaxIncidentIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		isHex := c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
		if !isHex && (i == 0 || c != '-') {
			return false
		}
	}
	return true
}

// Reason says why a request file was rejected.
type Reason string

const (
	// ReasonName: the file name is not one Submit produces.
	ReasonName Reason = "name"
	// ReasonSymlink: the entry is a symlink (never followed).
	ReasonSymlink Reason = "symlink"
	// ReasonNotRegular: the entry is a directory, FIFO, socket or device.
	ReasonNotRegular Reason = "not_regular"
	// ReasonOwner: the owner is neither uid 0 nor the running user.
	ReasonOwner Reason = "owner"
	// ReasonMode: a permission bit beyond 0600 is set.
	ReasonMode Reason = "mode"
	// ReasonOversize: the file is larger than MaxFileSize.
	ReasonOversize Reason = "oversize"
	// ReasonUntrusted: the file passed the first look but failed the trust
	// checks when it was opened (it was swapped or changed meanwhile).
	ReasonUntrusted Reason = "untrusted"
	// ReasonUnreadable: the file could not be read.
	ReasonUnreadable Reason = "unreadable"
	// ReasonMalformed: the content is not one JSON object of the known shape.
	ReasonMalformed Reason = "malformed"
	// ReasonSchema: schema_version is not SchemaVersion.
	ReasonSchema Reason = "schema"
	// ReasonAction: the action is not ack or close.
	ReasonAction Reason = "action"
	// ReasonIncidentID: the incident ID is not shaped like one.
	ReasonIncidentID Reason = "incident_id"
)

// Rejection is the reason a file was not accepted. Detail is a short
// description made by this package; it can contain text derived from the file
// (a name), so the daemon cleans it like any other untrusted text.
type Rejection struct {
	Reason Reason
	Detail string
}

// Item is one entry of the requests directory: either a parsed Request or a
// Rejection.
type Item struct {
	// Name is the entry name exactly as the directory holds it, to pass raw
	// to Remove. It is untrusted: for an entry not named as Submit names
	// them it is whatever someone chose (up to 255 bytes, escape sequences,
	// newlines, a backslash), so the daemon cleans it before it reaches the
	// audit log or any output, and still hands the raw value to Remove.
	Name string
	// Request is set when Rejection is nil.
	Request Request
	// Rejection is non-nil when the file was not accepted.
	Rejection *Rejection
}

// Accepted reports whether the item holds a usable Request.
func (it Item) Accepted() bool { return it.Rejection == nil }

// Batch is the result of one Pending call.
type Batch struct {
	// Items are at most MaxPending entries named as Submit names them, in
	// name order.
	Items []Item
	// More is true when further such files were left for the next call.
	More bool
	// Stray are at most MaxStray entries of any other name, in name order,
	// each a rejection with ReasonName. They were not opened and do not count
	// toward MaxPending.
	Stray []Item
	// StrayMore is true when further stray entries were left.
	StrayMore bool
	// Overfull is true when the directory holds more than MaxExamined
	// entries: the call examined that many and did not look at the rest.
	Overfull bool
}

type wireRequest struct {
	SchemaVersion int       `json:"schema_version"`
	Action        string    `json:"action"`
	IncidentID    string    `json:"incident_id"`
	Note          string    `json:"note"`
	RequestedAt   time.Time `json:"requested_at"`
}

var nameRE = regexp.MustCompile(`^req-[0-9]{20}-[0-9a-f]{32}$`)

// wireKeys are the keys of a request file, spelled exactly.
var wireKeys = map[string]bool{
	"schema_version": true, "action": true, "incident_id": true,
	"note": true, "requested_at": true,
}

// Hooks the tests replace.
var (
	ownerOf securefile.OwnerOf // nil: securefile.DefaultOwnerOf
	getuid  = os.Getuid
	now     = time.Now
	// maxExamined is MaxExamined; tests make it small.
	maxExamined = MaxExamined
	// afterList runs between listing the names and looking at them.
	afterList = func() {}
	// afterDirOpen runs between the trust check of the requests directory and
	// the second look at it.
	afterDirOpen = func() {}
	// readCapped reads one request file.
	readCapped = func(d *securefile.Dir, name string) ([]byte, error) {
		return d.ReadCapped(name, MaxFileSize)
	}
)

func owner(fi fs.FileInfo) (int, error) {
	if ownerOf != nil {
		return ownerOf(fi)
	}
	return securefile.DefaultOwnerOf(fi)
}

func trustedOwner(uid int) bool { return uid == 0 || uid == getuid() }

func newName() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	ns := now().UnixNano()
	if ns < 0 {
		ns = 0
	}
	return fmt.Sprintf("req-%020d-%s", ns, hex.EncodeToString(b[:])), nil
}

func requestsPath(stateDir string) string { return filepath.Join(stateDir, DirName) }

// handle is the opened requests directory: the trusted securefile directory
// for reading and writing files, and a root on the same path for listing,
// looking at entries and removing them.
type handle struct {
	dir  *securefile.Dir
	root *os.Root
}

func (h *handle) Close() {
	h.root.Close()
	h.dir.Close()
}

// checkDir applies the directory rules to the info of the requests directory:
// a real directory, owned by uid 0 or the running user, not writable by group
// or other.
func checkDir(path string, fi fs.FileInfo) error {
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s: must be a real directory, it is a symlink: %w", path, securefile.ErrUntrusted)
	case !fi.IsDir():
		return fmt.Errorf("%s: must be a directory: %w", path, securefile.ErrUntrusted)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s: permissions 0%03o allow group or other writes: %w", path, fi.Mode().Perm(), securefile.ErrUntrusted)
	}
	uid, err := owner(fi)
	if err != nil {
		return err
	}
	if !trustedOwner(uid) {
		return fmt.Errorf("%s: owned by uid %d: %w", path, uid, securefile.ErrUntrusted)
	}
	return nil
}

// open checks the state directory, then opens the requests directory below it
// (created with mode 0700 when create is set). A missing requests directory
// without create is fs.ErrNotExist.
//
// The requests directory is looked at three times: the path before the
// securefile directory is opened (it must pass the directory rules), the
// securefile directory itself (the same rules, in securefile), and the root
// opened afterwards for listing and removing (the rules again, on the root's
// own look at "."). The root must also be the directory the first look saw. So
// whichever directory the root ends up on is a trusted one, and a swap of the
// path between the steps is caught unless every directory it passes through is
// a trusted one. What remains is a swap between two trusted directories by
// someone who can rename in the state directory, which is uid 0 or the running
// user: the securefile directory and the root would then name different
// directories, which the checks cannot tell apart.
func open(stateDir string, create bool) (*handle, error) {
	st, err := securefile.OpenDir(stateDir, false, ownerOf)
	if err != nil {
		return nil, err
	}
	st.Close()
	path := requestsPath(stateDir)
	if create {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := checkDir(path, before); err != nil {
		return nil, err
	}
	d, err := securefile.OpenDir(path, false, ownerOf)
	if err != nil {
		return nil, err
	}
	afterDirOpen()
	root, err := os.OpenRoot(d.Path())
	if err != nil {
		d.Close()
		return nil, err
	}
	ri, err := root.Lstat(".")
	if err == nil {
		err = checkDir(d.Path(), ri)
	}
	if err == nil && !os.SameFile(before, ri) {
		err = fmt.Errorf("%s: changed while it was being opened: %w", d.Path(), securefile.ErrUntrusted)
	}
	if err != nil {
		root.Close()
		d.Close()
		return nil, err
	}
	return &handle{dir: d, root: root}, nil
}

// Submit writes req as a new file in the requests directory below stateDir
// and returns the file name. The state directory must exist and be trusted;
// the requests directory is created with mode 0700. The file is created with
// mode 0600 under an unpredictable name, written to a temporary file in the
// same directory (created exclusively, links not followed) and renamed into
// place, so a reader sees all of it or none of it. The name is 128 random
// bits behind the time, so a collision with an existing file is not a case
// that needs handling.
//
// The request is validated like Pending validates a file (a Note that is not
// valid UTF-8 is refused, since the encoding would replace its bad bytes and
// change its length; a RequestedAt the encoding cannot represent, a year
// outside 0 to 9999, is refused too); a zero RequestedAt is filled with the
// current time. Note must stay raw: the caller does not clean it, the daemon
// does.
func Submit(stateDir string, req Request) (string, error) {
	if !req.Action.Valid() {
		return "", fmt.Errorf("%w: action %q is not ack or close", ErrInvalidRequest, string(req.Action))
	}
	if !ValidIncidentID(req.IncidentID) {
		return "", fmt.Errorf("%w: malformed incident ID", ErrInvalidRequest)
	}
	if !utf8.ValidString(req.Note) {
		return "", fmt.Errorf("%w: note is not valid UTF-8", ErrInvalidRequest)
	}
	if len(req.Note) > MaxNoteBytes {
		return "", fmt.Errorf("%w: note is %d bytes, the limit is %d", ErrInvalidRequest, len(req.Note), MaxNoteBytes)
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = now()
	}
	data, err := json.Marshal(wireRequest{
		SchemaVersion: SchemaVersion,
		Action:        string(req.Action),
		IncidentID:    req.IncidentID,
		Note:          req.Note,
		RequestedAt:   req.RequestedAt.UTC(),
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	h, err := open(stateDir, true)
	if err != nil {
		return "", err
	}
	defer h.Close()
	name, err := newName()
	if err != nil {
		return "", err
	}
	if err := h.dir.WriteAtomic(name, append(data, '\n'), MaxFileSize); err != nil {
		return "", err
	}
	return name, nil
}

// Pending lists the request files below stateDir, in name order, at most
// MaxPending per call (see the package comment for the Stray list and the
// MaxExamined bound). A missing requests directory is an empty result. Files
// that fail a rule come back as rejected Items, not as an error; an error is
// returned only when the directories cannot be trusted or listed. Temporary
// files of a write in progress (securefile.TempPrefix) are ignored.
func Pending(stateDir string) (Batch, error) {
	h, err := openExisting(stateDir)
	if err != nil || h == nil {
		return Batch{}, err
	}
	defer h.Close()
	l, err := list(h.root)
	if err != nil {
		return Batch{}, err
	}
	afterList()
	b := Batch{Overfull: l.overfull}
	names := l.requests
	if len(names) > MaxPending {
		names = names[:MaxPending]
		b.More = true
	}
	stray := l.stray
	if len(stray) > MaxStray {
		stray = stray[:MaxStray]
		b.StrayMore = true
	}
	for _, name := range stray {
		b.Stray = append(b.Stray, reject(name, ReasonName, "unexpected file name %q", name))
	}
	for _, name := range names {
		if it, ok := h.look(name); ok {
			b.Items = append(b.Items, it)
		}
	}
	return b, nil
}

// openExisting is open without create. A requests directory that was never
// created is (nil, nil); a missing state directory is an error.
func openExisting(stateDir string) (*handle, error) {
	h, err := open(stateDir, false)
	if errors.Is(err, fs.ErrNotExist) {
		st, serr := securefile.OpenDir(stateDir, false, ownerOf)
		if serr != nil {
			return nil, serr
		}
		st.Close()
		return nil, nil
	}
	return h, err
}

// listing is what one pass over the directory found, each list sorted by name.
type listing struct {
	requests []string // named as Submit names them
	stray    []string // any other name
	temps    []string // securefile.TempPrefix
	overfull bool
}

// listChunk is the number of entries read from the directory at a time.
const listChunk = 256

// list reads the names of the directory in chunks, at most maxExamined of
// them, and sorts them into the three kinds.
func list(root *os.Root) (listing, error) {
	f, err := root.Open(".")
	if err != nil {
		return listing{}, err
	}
	defer f.Close()
	var l listing
	examined := 0
	for {
		n := listChunk
		if left := maxExamined - examined; left < n {
			n = left
		}
		if n <= 0 {
			// The limit is reached: is there anything left?
			ents, err := f.ReadDir(1)
			if err != nil && !errors.Is(err, io.EOF) {
				return listing{}, err
			}
			l.overfull = len(ents) > 0
			break
		}
		ents, err := f.ReadDir(n)
		for _, e := range ents {
			examined++
			switch name := e.Name(); {
			case strings.HasPrefix(name, securefile.TempPrefix):
				l.temps = append(l.temps, name)
			case nameRE.MatchString(name):
				l.requests = append(l.requests, name)
			default:
				l.stray = append(l.stray, name)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return listing{}, err
		}
	}
	sort.Strings(l.requests)
	sort.Strings(l.stray)
	sort.Strings(l.temps)
	return l, nil
}

func reject(name string, r Reason, format string, args ...any) Item {
	return Item{Name: name, Rejection: &Rejection{Reason: r, Detail: fmt.Sprintf(format, args...)}}
}

// look judges one entry whose name is one Submit produces. ok is false when the entry vanished meanwhile (the
// daemon consumed it, or it was removed) and there is nothing to report.
func (h *handle) look(name string) (it Item, ok bool) {
	fi, err := h.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return Item{}, false
	}
	if err != nil {
		return reject(name, ReasonUnreadable, "cannot look at the file: %v", err), true
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return reject(name, ReasonSymlink, "is a symlink, it is not followed"), true
	case !fi.Mode().IsRegular():
		return reject(name, ReasonNotRegular, "is not a regular file (%s)", fi.Mode().Type()), true
	}
	uid, err := owner(fi)
	if err != nil {
		return reject(name, ReasonUnreadable, "cannot tell who owns the file: %v", err), true
	}
	if !trustedOwner(uid) {
		return reject(name, ReasonOwner, "owned by uid %d", uid), true
	}
	const allBits = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if extra := fi.Mode() & allBits &^ 0o600; extra != 0 {
		return reject(name, ReasonMode, "mode %s has bits beyond 0600", fi.Mode()&allBits), true
	}
	// The size is judged by ReadCapped before it reads a byte, and again
	// while it reads.
	data, err := readCapped(h.dir, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Item{}, false
	case errors.Is(err, securefile.ErrTooLarge):
		return reject(name, ReasonOversize, "larger than %d bytes", MaxFileSize), true
	case errors.Is(err, securefile.ErrUntrusted), errors.Is(err, securefile.ErrChanged):
		return reject(name, ReasonUntrusted, "failed the trust checks when it was opened"), true
	case err != nil:
		return reject(name, ReasonUnreadable, "cannot read the file: %v", err), true
	}
	req, rej := parse(data)
	if rej != nil {
		return Item{Name: name, Rejection: rej}, true
	}
	return Item{Name: name, Request: req}, true
}

func parse(data []byte) (Request, *Rejection) {
	bad := func(r Reason, format string, args ...any) (Request, *Rejection) {
		return Request{}, &Rejection{Reason: r, Detail: fmt.Sprintf(format, args...)}
	}
	// The schema is judged first and on its own, so that a file of a future
	// schema (with fields this version does not know) is reported as that,
	// not as malformed. Unmarshal also refuses data after the JSON value.
	var probe struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return bad(ReasonMalformed, "not a JSON object")
	}
	if probe.SchemaVersion == nil || *probe.SchemaVersion != SchemaVersion {
		return bad(ReasonSchema, "schema_version is not %d", SchemaVersion)
	}
	if err := checkKeys(data); err != nil {
		return bad(ReasonMalformed, "%v", err)
	}
	var w wireRequest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return bad(ReasonMalformed, "does not have the shape of a request")
	}
	if w.Action != string(ActionAck) && w.Action != string(ActionClose) {
		return bad(ReasonAction, "action is not ack or close")
	}
	if !ValidIncidentID(w.IncidentID) {
		return bad(ReasonIncidentID, "malformed incident ID")
	}
	if len(w.Note) > MaxNoteBytes {
		return bad(ReasonMalformed, "note is %d bytes, the limit is %d", len(w.Note), MaxNoteBytes)
	}
	return Request{
		Action:      Action(w.Action),
		IncidentID:  w.IncidentID,
		Note:        w.Note,
		RequestedAt: w.RequestedAt,
	}, nil
}

// checkKeys walks the top-level keys of the JSON object in data and refuses a
// key that is repeated or that is not spelled exactly as in wireKeys. The
// decoder alone would take the last of two equal keys and match a key whatever
// its case, so a file could say one thing to a reader that picks the first and
// another to this one.
func checkKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return errors.New("not a JSON object")
		}
		key, _ := t.(string)
		if !wireKeys[key] {
			return errors.New("a key is unknown or not spelled exactly")
		}
		if seen[key] {
			return errors.New("a key is repeated")
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return errors.New("not a JSON object")
		}
	}
	return nil
}

// Remove deletes the entry name of the requests directory below stateDir,
// after the daemon has applied and audited it or has audited its rejection.
// name is passed raw from Item.Name; only a single path component is accepted
// (not empty, not "." or "..", no "/" and no NUL), and a temporary file
// (securefile.TempPrefix) is never removed here: it belongs to a write in
// progress (see SweepTemp). Anything else in the directory can be removed, a
// directory with its content included, and nothing outside the requests
// directory is reachable. A symlink is removed itself, never its target. An
// entry that is already gone is not an error, so a repeated Remove is
// harmless.
func Remove(stateDir, name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") ||
		strings.HasPrefix(name, securefile.TempPrefix) {
		return fmt.Errorf("%w: %q", securefile.ErrInvalidName, name)
	}
	h, err := openExisting(stateDir)
	if err != nil || h == nil {
		return err
	}
	defer h.Close()
	if err := h.root.RemoveAll(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// SweepTemp removes the temporary files (securefile.TempPrefix) of the
// requests directory below stateDir whose last modification is older than
// olderThan, and returns how many it removed. A Submit that is killed between
// creating its temporary file and renaming it leaves one, and nothing else
// removes it. olderThan must be positive: the age is what keeps a write in
// progress safe, so choose it well above the time a Submit takes. At most
// MaxExamined directory entries are examined per call. A missing requests
// directory is zero files and no error. A file that cannot be removed does
// not stop the others; the errors come back joined.
func SweepTemp(stateDir string, olderThan time.Duration) (int, error) {
	if olderThan <= 0 {
		return 0, fmt.Errorf("requests: SweepTemp needs a positive age, got %s", olderThan)
	}
	h, err := openExisting(stateDir)
	if err != nil || h == nil {
		return 0, err
	}
	defer h.Close()
	l, err := list(h.root)
	if err != nil {
		return 0, err
	}
	cutoff := now().Add(-olderThan)
	removed := 0
	var errs []error
	for _, name := range l.temps {
		fi, err := h.root.Lstat(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !fi.ModTime().Before(cutoff) {
			continue
		}
		switch err := h.root.RemoveAll(name); {
		case err == nil:
			removed++
		case !errors.Is(err, fs.ErrNotExist):
			errs = append(errs, err)
		}
	}
	return removed, errors.Join(errs...)
}
