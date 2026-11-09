//go:build !unix

package probes

import "os"

// openFlags: this platform has no O_NOFOLLOW to ask for; the regular-file
// check in ReadFile still applies to what the path resolves to.
const openFlags = os.O_RDONLY
