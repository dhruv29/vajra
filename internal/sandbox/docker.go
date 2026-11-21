package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	killTimeout      = 10 * time.Second
	nameRandBytes    = 8
	inspectOutputCap = 4 << 10
)

// Runner runs a Spec and returns what it produced.
type Runner interface {
	Run(ctx context.Context, spec Spec) (Result, error)
}

// execFunc runs the docker CLI with args and returns its exit code. A non-zero
// exit is not an error; err is for failures to run the CLI at all.
type execFunc func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error)

// Docker runs specs through the docker CLI.
type Docker struct {
	exec execFunc
}

// NewDocker returns a runner that uses the docker binary on PATH.
func NewDocker() *Docker {
	return &Docker{exec: dockerExec}
}

// hostEnvForCLI is the only host environment the docker CLI itself receives.
// The container gets none of it.
var hostEnvForCLI = []string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY"}

func dockerExec(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.Env = []string{}
	for _, key := range hostEnvForCLI {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// Run executes spec in a new container and removes the container afterwards.
func (d *Docker) Run(ctx context.Context, spec Spec) (Result, error) {
	spec = spec.withDefaults()
	name, err := containerName()
	if err != nil {
		return Result{}, err
	}
	args, err := DockerArgs(spec, name)
	if err != nil {
		return Result{}, err
	}

	runCtx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	stdout := &cappedBuffer{limit: spec.OutputCap}
	stderr := &cappedBuffer{limit: spec.OutputCap}
	var stdin io.Reader
	if spec.Stdin != nil {
		stdin = bytes.NewReader(spec.Stdin)
	}
	code, err := d.exec(runCtx, args, stdin, stdout, stderr)

	result := Result{
		ExitCode:  code,
		Stdout:    stdout.buf.Bytes(),
		Stderr:    stderr.buf.Bytes(),
		Truncated: stdout.truncated || stderr.truncated,
	}
	if runCtx.Err() != nil {
		// Killing the CLI does not stop the container, so stop it by name.
		d.kill(name)
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			result.TimedOut = true
			return result, nil
		}
		return result, runCtx.Err()
	}
	if err != nil {
		return result, fmt.Errorf("sandbox: run docker: %w", err)
	}
	return result, nil
}

func (d *Docker) kill(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), killTimeout)
	defer cancel()
	// Best effort: the container may already be gone.
	_, _ = d.exec(ctx, []string{"kill", name}, nil, io.Discard, io.Discard)
}

func containerName() (string, error) {
	raw := make([]byte, nameRandBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("sandbox: container name: %w", err)
	}
	return "vajra-" + hex.EncodeToString(raw), nil
}

// cappedBuffer keeps the first limit bytes and discards the rest, so a noisy
// tool cannot exhaust memory.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	if room <= 0 {
		c.truncated = c.truncated || len(p) > 0
		return len(p), nil
	}
	if len(p) > room {
		c.buf.Write(p[:room])
		c.truncated = true
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}

// RequireInternalNetwork fails unless name is exactly the name of a Docker
// network created with --internal. A task attached to any other network would
// have a route that does not pass through the egress gate.
func (d *Docker) RequireInternalNetwork(ctx context.Context, name string) error {
	if err := validateNetwork(name); err != nil {
		return err
	}
	if name == NetworkNone {
		return nil
	}
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = inspectOutputCap, inspectOutputCap
	code, err := d.exec(ctx, []string{"network", "inspect", "--format", "{{.Internal}} {{.Name}}", name}, nil, &stdout, &stderr)
	if err != nil {
		return fmt.Errorf("sandbox: inspect network %q: %w", name, err)
	}
	if code != 0 {
		return fmt.Errorf("sandbox: network %q does not exist: create it with docker network create --internal", name)
	}
	// Docker also resolves a network by ID prefix, so the name it reports must
	// be the name that was asked for.
	if got := strings.TrimSpace(stdout.buf.String()); got != "true "+name {
		return fmt.Errorf("sandbox: network %q is not an internal network, so tasks on it could bypass the gate", name)
	}
	return nil
}
