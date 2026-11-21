package portscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/sandbox"
)

const (
	jobInputLimit = 1 << 20
	resultCap     = 8 << 20
	// perAttempt is how long one connection attempt may take.
	perAttempt = 5 * time.Second
)

// Job is the input of "vajra portscan", which runs inside the sandbox.
type Job struct {
	// Gate is the SOCKS5 address of the egress gate on the task network.
	Gate     string   `json:"gate"`
	Hosts    []string `json:"hosts"`
	Ports    []int    `json:"ports"`
	Expected []int    `json:"expected"`
}

// RunJob is the body of the "vajra portscan" command: read a job, try the
// connections through the gate, write the result.
func RunJob(ctx context.Context, in io.Reader, out io.Writer) error {
	var job Job
	if err := json.NewDecoder(io.LimitReader(in, jobInputLimit)).Decode(&job); err != nil {
		return fmt.Errorf("portscan: read job: %w", err)
	}
	if _, _, err := net.SplitHostPort(job.Gate); err != nil {
		return fmt.Errorf("portscan: gate address %q must be host:port", job.Gate)
	}
	dial, refused := SOCKS5Dialer(job.Gate)
	scanner, err := New(dial, Options{Hosts: job.Hosts, Ports: job.Ports, Expected: job.Expected, Timeout: perAttempt, Refused: refused})
	if err != nil {
		return err
	}
	result, err := scanner.Run(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}

// Runner starts "vajra portscan" in a sandbox container on the task network,
// so that every connection attempt goes through the gate.
type Runner struct {
	Sandbox sandbox.Runner
	// Image must contain the vajra binary as its entrypoint.
	Image   string
	Network string
	// Gate is the gate's SOCKS5 address as seen from the task network.
	Gate     string
	Timeout  time.Duration
	Hosts    []string
	Ports    []int
	Expected []int
}

// Validate reports the first missing setting.
func (r *Runner) Validate() error {
	switch {
	case r.Sandbox == nil:
		return errors.New("portscan: a sandbox runner is required")
	case r.Image == "" || r.Gate == "":
		return errors.New("portscan: an image and the gate's SOCKS5 address are required")
	case r.Network == "" || r.Network == sandbox.NetworkNone:
		return errors.New("portscan: an internal network is required")
	case r.Timeout <= 0:
		return errors.New("portscan: a timeout is required")
	}
	// The same checks the scan itself makes, so a bad list fails early.
	_, err := New(func(context.Context, string) (net.Conn, error) { return nil, errors.New("unused") },
		Options{Hosts: r.Hosts, Ports: r.Ports, Expected: r.Expected, Timeout: perAttempt})
	return err
}

// Scan tries every configured host and port.
func (r *Runner) Scan(ctx context.Context) (Result, error) {
	return r.run(ctx, r.Hosts, r.Ports)
}

// Reproduce tries the one address behind f again.
func (r *Runner) Reproduce(ctx context.Context, f finding.Finding) (bool, error) {
	if f.Source != Source {
		return false, errors.New("portscan: not a finding from this scanner")
	}
	host, port, ok := r.configured(f.Target)
	if !ok {
		return false, fmt.Errorf("portscan: %s is not one of the configured addresses", f.Target)
	}
	result, err := r.run(ctx, []string{host}, []int{port})
	if err != nil {
		return false, err
	}
	if len(result.Refused) > 0 {
		return false, fmt.Errorf("portscan: the gate no longer allows %s", f.Target)
	}
	return len(result.Open) > 0, nil
}

// configured parses "tcp://host:port" and checks it against the lists.
func (r *Runner) configured(target string) (string, int, bool) {
	address, found := strings.CutPrefix(target, "tcp://")
	if !found {
		return "", 0, false
	}
	for _, host := range r.Hosts {
		for _, port := range r.Ports {
			if net.JoinHostPort(host, fmt.Sprint(port)) == address {
				return host, port, true
			}
		}
	}
	return "", 0, false
}

func (r *Runner) run(ctx context.Context, hosts []string, ports []int) (Result, error) {
	if err := r.Validate(); err != nil {
		return Result{}, err
	}
	stdin, err := json.Marshal(Job{Gate: r.Gate, Hosts: hosts, Ports: ports, Expected: r.Expected})
	if err != nil {
		return Result{}, fmt.Errorf("portscan: encode job: %w", err)
	}
	out, err := r.Sandbox.Run(ctx, sandbox.Spec{
		Image: r.Image, Argv: []string{"portscan"}, Network: r.Network,
		Timeout: r.Timeout, OutputCap: resultCap, Stdin: stdin,
	})
	if err != nil {
		return Result{}, fmt.Errorf("portscan: %w", err)
	}
	if out.TimedOut {
		return Result{}, fmt.Errorf("portscan: timed out after %s", r.Timeout)
	}
	if out.ExitCode != 0 || out.Truncated {
		return Result{}, fmt.Errorf("portscan: exit code %d: %s", out.ExitCode, strings.TrimSpace(string(out.Stderr)))
	}
	var result Result
	if err := json.Unmarshal(bytes.TrimSpace(out.Stdout), &result); err != nil {
		return Result{}, fmt.Errorf("portscan: decode result: %w", err)
	}
	return result, nil
}
