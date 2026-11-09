//go:build !unix

package execx

import (
	"os"
	"os/exec"
)

// configureKill kills only the direct child on platforms without process groups.
func configureKill(cmd *exec.Cmd) {
	cmd.WaitDelay = waitDelay
}

func killGroup(*exec.Cmd) {}

func signaled(*os.ProcessState) bool { return false }
