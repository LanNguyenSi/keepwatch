//go:build !unix

package probes

import "os"

// openFlags: this platform has no O_NOFOLLOW to ask for; the regular-file
// check in ReadFile still applies to what the path resolves to.
const openFlags = os.O_RDONLY

const nonblockRead = os.O_RDONLY

// ownerUID: ownership is not available here, so every ownership check fails
// closed.
func ownerUID(os.FileInfo) (uint32, bool) { return 0, false }
