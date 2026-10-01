package runner

import (
	"context"
	"os"
	"os/exec"
)

// Runner isolates host commands and read-only file access for deterministic tests.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
	LookPath(name string) (string, error)
	ReadFile(name string) ([]byte, error)
}

type System struct{}

func (System) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr []byte
	var err error
	stdout, err = cmd.Output()
	if exitErr, ok := err.(*exec.ExitError); ok {
		stderr = exitErr.Stderr
	}
	return string(stdout), string(stderr), err
}

func (System) LookPath(name string) (string, error) { return exec.LookPath(name) }
func (System) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }
