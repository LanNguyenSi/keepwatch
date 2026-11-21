package watch

import (
	"errors"
	"fmt"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/requests"
)

// maxRequestNote is the longest note, in bytes of its cleaned text, that a
// request record carries. The note goes last in the summary, so the cut of
// the whole summary to maxRecordSummary keeps the rest of the record.
const maxRequestNote = 256

// applyRequests applies the accepted requests of one listing, at most
// requests.MaxPending per pass, and removes each one it applied or applied
// before. seen collects the names
// it looked at, so the by-name memory keeps them.
//
// A request is applied, audited and then removed. A name whose record was
// written is remembered (rejAudited, the memory of the rejected files): while
// Remove keeps failing, the next passes only try Remove again and neither
// apply nor audit it a second time. The memory ends when the name leaves the
// listing, and with the process: a restart replays such a request, which then
// finds its target state reached (see applyRequest).
func (d *Daemon) applyRequests(items []requests.Item, seen map[string]bool) error {
	n := 0
	for _, it := range items {
		if !it.Accepted() {
			continue
		}
		seen[it.Name] = true
		if !d.rejAudited[it.Name] {
			// requests.Pending returns at most MaxPending items; this guards
			// against RequestOps that return more. It counts the requests
			// that write a record, and one beyond it is left as it is.
			if n == requests.MaxPending {
				continue
			}
			n++
			if err := d.applyRequest(it); err != nil {
				return err
			}
			d.rejAudited[it.Name] = true
		}
		// A failed Remove is tried again on the next pass, without a new record.
		_ = d.deps.Requests.Remove(it.Name)
	}
	return nil
}

// applyRequest moves the incident of one accepted request and audits the
// outcome. A transition the store refuses (an unknown, retired or evicted
// id, a target state already reached, any move CanTransition does not allow)
// is audited as request_rejected with the reason and changes nothing. A
// store that cannot save is fatal, like every other store write; the request
// stays and is replayed after the restart.
func (d *Daemon) applyRequest(it requests.Item) error {
	req := it.Request
	var (
		in  incident.Incident
		err error
	)
	switch req.Action {
	case requests.ActionAck:
		in, err = d.deps.Incidents.Ack(req.IncidentID)
	case requests.ActionClose:
		in, err = d.deps.Incidents.Close(req.IncidentID)
	default:
		in, _ = d.deps.Incidents.Get(req.IncidentID)
		return d.requestRecord(audit.RequestRejected, in, d.requestText(it, "rejected: the action is neither ack nor close"))
	}
	var te *incident.TransitionError
	if errors.As(err, &te) {
		// The refused incident exists: its record carries its id.
		in, _ = d.deps.Incidents.Get(te.ID)
	}
	switch {
	case err == nil && req.Action == requests.ActionAck:
		return d.requestRecord(audit.IncidentAck, in, d.requestText(it, "acked"))
	case err == nil:
		return d.requestRecord(audit.IncidentClose, in, d.requestText(it, "closed"))
	case te != nil && te.From == te.To:
		return d.requestRecord(audit.RequestRejected, in, d.requestText(it,
			fmt.Sprintf("rejected: the incident is already %s (a second request, or a replay after a crash before the request was removed)", te.To)))
	case te != nil:
		return d.requestRecord(audit.RequestRejected, in, d.requestText(it,
			fmt.Sprintf("rejected: the incident cannot move from %s to %s", te.From, te.To)))
	case errors.Is(err, incident.ErrUnknownIncident):
		return d.requestRecord(audit.RequestRejected, incident.Incident{}, d.requestText(it,
			"rejected: no such incident (unknown, retired or evicted)"))
	}
	return fmt.Errorf("watch: incident store: %w", err)
}

// requestText is the summary of a request record. Name, incident id and note
// are untrusted and cleaned here; the note is cleaned first and then cut to
// maxRequestNote. RequestedAt is the writer's claim and appears only as such:
// the record time is the daemon clock (appendRecord).
func (d *Daemon) requestText(it requests.Item, outcome string) string {
	req := it.Request
	return fmt.Sprintf("request %s for incident %s %s; requested at %s (the writer's claim); note: %s",
		d.safe(it.Name), d.safe(req.IncidentID), outcome, req.RequestedAt.UTC().Format(time.RFC3339Nano),
		cutBytes(d.safe(req.Note), maxRequestNote))
}

// requestRecord is the one function that writes the records of applied
// requests: incident_ack, incident_close and request_rejected for a request
// that cannot be applied. These are incident records outside admit and its
// per-rule budget, on purpose: the spool is writable by root only, so they
// are not in an outsider's hands, and applyRequests bounds them to
// requests.MaxPending per pass. TestIncidentRecordsOnlyThroughAdmit allows
// exactly this function, called from applyRequest with exactly these kinds.
func (d *Daemon) requestRecord(kind audit.Kind, in incident.Incident, summary string) error {
	return d.record(kind, in.ID, string(in.Fingerprint), summary)
}
