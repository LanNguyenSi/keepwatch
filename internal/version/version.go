// Package version holds build metadata, set at link time with -ldflags -X.
package version

// These are overridden by the linker; see the Makefile.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a one-line description of the build.
func String() string {
	return "keepwatch " + Version + " (commit " + Commit + ", built " + Date + ")"
}
