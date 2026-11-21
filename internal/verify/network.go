package verify

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/scope"
)

// PortTarget parses a network finding's target, "tcp://host:port".
func PortTarget(target string) (string, uint16, error) {
	address, ok := strings.CutPrefix(target, "tcp://")
	if !ok {
		return "", 0, fmt.Errorf("target %q is not a tcp:// address", target)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("target %q is not host:port", target)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || host == "" {
		return "", 0, fmt.Errorf("target %q has no usable host and port", target)
	}
	return host, uint16(port), nil
}

// PortScopeStage checks that a network finding names an address the policy
// covers. It also serves as the evidence check: a finding whose target cannot
// be read as an address cannot be re-tested.
type PortScopeStage struct {
	Policy *scope.Policy
}

func (PortScopeStage) Name() string               { return "scope" }
func (PortScopeStage) FailStatus() finding.Status { return finding.OutOfScope }

func (s PortScopeStage) Check(_ context.Context, f finding.Finding) (finding.Outcome, string) {
	host, port, err := PortTarget(f.Target)
	if err != nil {
		return finding.Fail, err.Error()
	}
	if err := s.Policy.CheckTarget(host, port); err != nil {
		return finding.Fail, err.Error()
	}
	return finding.Pass, "address is in scope"
}
