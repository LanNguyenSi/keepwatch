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
// # Delivery
//
// Pending does not remove anything. The daemon decides the order of apply,
// audit and Remove, and with it whether a crash in between replays a request
// (remove after apply: at least once) or drops it (remove before apply: at
// most once). A rejected or consumed file that Remove cannot delete shows up
// again on the next Pending call.
//
// One Pending call looks at no more than MaxPending files, in name order, so
// a flood of files costs the daemon a bounded amount of work per pass (the
// names of the whole directory are listed, but only MaxPending files are
// opened and read). Names start with the submission time in nanoseconds, so
// name order is submission order for requests from one machine; the rest of
// the name is 128 random bits, which makes it unpredictable.
package requests

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

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
	// MaxIncidentIDBytes is the longest incident ID accepted.
	MaxIncidentIDBytes = 64
	// MaxPending is the largest number of files one Pending call opens and
	// returns. Rejected files count; ignored temporary files do not.
	MaxPending = 100
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
// MaxIncidentIDBytes ASCII letters, digits, "-" or "_". It checks the shape
// only; whether the incident exists is for the daemon.
func ValidIncidentID(id string) bool {
	if id == "" || len(id) > MaxIncidentIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
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
	// Name is the file name, to pass to Remove.
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
	// Items are at most MaxPending entries, in name order.
	Items []Item
	// More is true when further files were left for the next call.
	More bool
}

type wireRequest struct {
	SchemaVersion int       `json:"schema_version"`
	Action        string    `json:"action"`
	IncidentID    string    `json:"incident_id"`
	Note          string    `json:"note"`
	RequestedAt   time.Time `json:"requested_at"`
}

var nameRE = regexp.MustCompile(`^req-[0-9]{20}-[0-9a-f]{32}$`)

// Hooks the tests replace.
var (
	ownerOf securefile.OwnerOf // nil: securefile.DefaultOwnerOf
	getuid  = os.Getuid
	now     = time.Now
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

// open checks the state directory, then opens the requests directory below it
// (created with mode 0700 when create is set). A missing requests directory
// without create is fs.ErrNotExist.
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
	// The directory that is looked at here is the one the trust check of
	// OpenDir must see and the one the root must be opened on; a swap in
	// between makes the identities differ.
	before, err := os.Lstat(path)
	if err != nil {
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
	ri, rerr := root.Lstat(".")
	if rerr != nil || !os.SameFile(before, ri) {
		root.Close()
		d.Close()
		return nil, fmt.Errorf("%s: changed while it was being opened: %w", d.Path(), securefile.ErrUntrusted)
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
// The request is validated like Pending validates a file; a zero RequestedAt
// is filled with the current time. Note must stay raw: the caller does not
// clean it, the daemon does.
func Submit(stateDir string, req Request) (string, error) {
	if !req.Action.Valid() {
		return "", fmt.Errorf("%w: action %q is not ack or close", ErrInvalidRequest, string(req.Action))
	}
	if !ValidIncidentID(req.IncidentID) {
		return "", fmt.Errorf("%w: malformed incident ID", ErrInvalidRequest)
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
		return "", err
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
// MaxPending per call. A missing requests directory is an empty result. Files
// that fail a rule come back as rejected Items, not as an error; an error is
// returned only when the directories cannot be trusted or listed. Temporary
// files of a write in progress (securefile.TempPrefix) are ignored.
func Pending(stateDir string) (Batch, error) {
	h, err := openExisting(stateDir)
	if err != nil || h == nil {
		return Batch{}, err
	}
	defer h.Close()
	names, err := listNames(h.root)
	if err != nil {
		return Batch{}, err
	}
	afterList()
	var b Batch
	if len(names) > MaxPending {
		names = names[:MaxPending]
		b.More = true
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

func listNames(root *os.Root) ([]string, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ents, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), securefile.TempPrefix) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func reject(name string, r Reason, format string, args ...any) Item {
	return Item{Name: name, Rejection: &Rejection{Reason: r, Detail: fmt.Sprintf(format, args...)}}
}

// look judges one entry. ok is false when the entry vanished meanwhile (the
// daemon consumed it, or it was removed) and there is nothing to report.
func (h *handle) look(name string) (it Item, ok bool) {
	if !nameRE.MatchString(name) {
		return reject(name, ReasonName, "unexpected file name %q", name), true
	}
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

// Remove deletes the request file name below stateDir, after the daemon has
// applied and audited it or has audited its rejection. Only a single plain
// path component is accepted, and a temporary file (securefile.TempPrefix) is
// never removed here: it belongs to a write in progress. A symlink is removed
// itself, never its target. A file that is already gone is not an error, so a
// repeated Remove is harmless.
func Remove(stateDir, name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") ||
		strings.HasPrefix(name, securefile.TempPrefix) {
		return fmt.Errorf("%w: %q", securefile.ErrInvalidName, name)
	}
	h, err := openExisting(stateDir)
	if err != nil || h == nil {
		return err
	}
	defer h.Close()
	if err := h.root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
