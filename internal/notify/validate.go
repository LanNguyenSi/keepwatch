package notify

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// ValidateURL is the one rule for notify.ntfy.url, used by NewNtfy and by the
// configuration validator, so that a configuration that loads is always one
// NewNtfy accepts: an absolute URL with a host, no credentials (the token goes
// in token_file), no query or fragment, a port from 1 to 65535, and https, or
// http only for a loopback host.
//
// The messages never hold the URL: it may carry credentials, and a message may
// end up in a log or a notification.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	// u.Hostname is the host without its port: an authority like ":443" has
	// a Host but no host. A Host ending in ':' carries an empty port, which is
	// not a valid URL either.
	case err != nil || u.Hostname() == "" || strings.HasSuffix(u.Host, ":"):
		return errors.New("notify.ntfy.url is not a valid absolute URL")
	case u.User != nil:
		return errors.New("notify.ntfy.url must not hold credentials: the token goes in token_file")
	// A fragment, even an empty one, is a '#' in the text.
	case u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#"):
		return errors.New("notify.ntfy.url must not hold a query or a fragment")
	}
	if p := u.Port(); p != "" {
		// url.Parse accepts digits only; on overflow Atoi returns the largest int,
		// which is outside the range as well.
		if port, _ := strconv.Atoi(p); port < 1 || port > 65535 {
			return errors.New("notify.ntfy.url: the port must be between 1 and 65535")
		}
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && isLoopback(u.Hostname()):
	case u.Scheme == "http":
		return errors.New("notify.ntfy.url: http is only allowed for loopback hosts")
	default:
		return errors.New("notify.ntfy.url: the scheme must be https")
	}
	return nil
}

// ValidateTopic is the one rule for notify.ntfy.topic: 1 to 64 characters of
// A-Z a-z 0-9 _ -.
func ValidateTopic(topic string) error {
	if !topicRe.MatchString(topic) {
		return errors.New("notify.ntfy.topic must be 1 to 64 characters of A-Z a-z 0-9 _ -")
	}
	return nil
}
