//go:build !unix

package execx

import (
	"os/exec"
	"time"
)

// configureKill kills only the direct child on platforms without process groups.
func configureKill(cmd *exec.Cmd) {
	cmd.WaitDelay = 2 * time.Second
}
