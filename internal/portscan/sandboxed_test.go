package portscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dhruv29/vajra/internal/egress"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/scope"
)

type tableResolver map[string]string

func (r tableResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ip, ok := r[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return []netip.Addr{netip.MustParseAddr(ip)}, nil
}

type discardSink struct{}

func (discardSink) Record(egress.Event) error { return nil }

// realGate starts the gate's real SOCKS5 front end. In-scope connections to
// port 443 are redirected to a local listener; port 8081 is closed.
func realGate(t *testing.T) string {
	t.Helper()
	open, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { open.Close() })
	go func() {
		for {
			conn, err := open.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	policy, err := scope.New(scope.Config{Hosts: []string{"app.test"}, Ports: []int{443, 8081}})
	if err != nil {
		t.Fatal(err)
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasSuffix(address, ":443") {
			return (&net.Dialer{}).DialContext(ctx, network, open.Addr().String())
		}
		return nil, errors.New("connection refused")
	}
	guard, err := egress.NewGuard(policy, tableResolver{"app.test": "203.0.113.10", "other.test": "203.0.113.11"}, dial)
	if err != nil {
		t.Fatal(err)
	}
	server, err := egress.NewSOCKS5(guard, discardSink{})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Serve(ctx, listener) }()
	return listener.Addr().String()
}

func TestRunJobFindsOpenClosedAndRefusedPortsThroughTheRealGate(t *testing.T) {
	gate := realGate(t)
	job, _ := json.Marshal(Job{Gate: gate, Hosts: []string{"app.test", "other.test"}, Ports: []int{443, 8081}, Expected: []int{8081}})
	var out bytes.Buffer

	if err := RunJob(context.Background(), bytes.NewReader(job), &out); err != nil {
		t.Fatal(err)
	}

	var result Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(result.Open) != "[app.test:443]" {
		t.Fatalf("open = %v", result.Open)
	}
	if fmt.Sprint(result.Refused) != "[other.test:443 other.test:8081]" {
		t.Fatalf("refused = %v; the gate must refuse a host outside the scope", result.Refused)
	}
	if len(result.Findings) != 1 || result.Findings[0].Target != "tcp://app.test:443" || result.Findings[0].RuleID != "unexpected-open-port" {
		t.Fatalf("findings = %+v", result.Findings)
	}
}

func TestRunJobRejectsBadInput(t *testing.T) {
	for name, input := range map[string]string{
		"not json":     "nope",
		"no gate":      `{"hosts":["app.test"],"ports":[443]}`,
		"no hosts":     `{"gate":"gate:1080","ports":[443]}`,
		"bad port":     `{"gate":"gate:1080","hosts":["app.test"],"ports":[70000]}`,
		"gate no port": `{"gate":"gate","hosts":["app.test"],"ports":[443]}`,
	} {
		if err := RunJob(context.Background(), strings.NewReader(input), io.Discard); err == nil {
			t.Errorf("%s: RunJob succeeded", name)
		}
	}
}

func TestSOCKS5DialerReportsAGateThatIsDownOrBroken(t *testing.T) {
	dial, refused := SOCKS5Dialer("127.0.0.1:1")
	if _, err := dial(context.Background(), "app.test:443"); err == nil || refused(err) {
		t.Fatalf("err = %v; an unreachable gate is an error, not a refusal", err)
	}
	for _, address := range []string{"no-port", "app.test:notaport", ":443", strings.Repeat("a", 300) + ":443"} {
		if _, err := dial(context.Background(), address); err == nil {
			t.Errorf("%q was accepted", address)
		}
	}
	// A server that is not a SOCKS5 gate.
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			conn.Close()
		}
	}()
	notGate, _ := SOCKS5Dialer(listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := notGate(ctx, "app.test:443"); err == nil {
		t.Fatal("a non-SOCKS server was accepted as the gate")
	}
}

type fakeSandbox struct {
	specs  []sandbox.Spec
	result sandbox.Result
	err    error
}

func (f *fakeSandbox) Run(_ context.Context, spec sandbox.Spec) (sandbox.Result, error) {
	f.specs = append(f.specs, spec)
	return f.result, f.err
}

func newRunner(s sandbox.Runner) *Runner {
	return &Runner{
		Sandbox: s, Image: "vajra:local", Network: "vajra-task-net", Gate: "gate:1080", Timeout: time.Minute,
		Hosts: []string{"app.test"}, Ports: []int{443, 5432}, Expected: []int{443},
	}
}

func TestRunnerSendsTheJobToASandboxOnTheTaskNetwork(t *testing.T) {
	fake := &fakeSandbox{result: sandbox.Result{Stdout: []byte(`{"open":["app.test:5432"],"refused":[],"findings":[{"id":"f1","target":"tcp://app.test:5432"}]}` + "\n")}}

	result, err := newRunner(fake).Scan(context.Background())

	if err != nil || len(result.Findings) != 1 || result.Open[0] != "app.test:5432" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	spec := fake.specs[0]
	var job Job
	if err := json.Unmarshal(spec.Stdin, &job); err != nil {
		t.Fatal(err)
	}
	if spec.Network != "vajra-task-net" || spec.Image != "vajra:local" || fmt.Sprint(spec.Argv) != "[portscan]" ||
		job.Gate != "gate:1080" || fmt.Sprint(job.Ports) != "[443 5432]" || fmt.Sprint(job.Expected) != "[443]" {
		t.Fatalf("spec = %+v, job = %+v", spec, job)
	}
}

func TestRunnerReproduceTriesOnlyTheOneAddress(t *testing.T) {
	f := finding.Finding{Source: Source, Target: "tcp://app.test:5432"}
	for name, tc := range map[string]struct {
		stdout string
		want   bool
		fails  bool
	}{
		"still open":       {`{"open":["app.test:5432"],"refused":[],"findings":[]}`, true, false},
		"now closed":       {`{"open":[],"refused":[],"findings":[]}`, false, false},
		"now out of scope": {`{"open":[],"refused":["app.test:5432"],"findings":[]}`, false, true},
	} {
		fake := &fakeSandbox{result: sandbox.Result{Stdout: []byte(tc.stdout)}}
		got, err := newRunner(fake).Reproduce(context.Background(), f)
		if got != tc.want || tc.fails != (err != nil) {
			t.Errorf("%s: open = %v, err = %v", name, got, err)
		}
		var job Job
		_ = json.Unmarshal(fake.specs[0].Stdin, &job)
		if fmt.Sprint(job.Hosts) != "[app.test]" || fmt.Sprint(job.Ports) != "[5432]" {
			t.Errorf("%s: re-test tried %v %v", name, job.Hosts, job.Ports)
		}
	}
	for name, other := range map[string]finding.Finding{
		"another scanner":   {Source: "nuclei", Target: "tcp://app.test:5432"},
		"unlisted port":     {Source: Source, Target: "tcp://app.test:22"},
		"not a tcp address": {Source: Source, Target: "https://app.test"},
	} {
		fake := &fakeSandbox{}
		if _, err := newRunner(fake).Reproduce(context.Background(), other); err == nil || len(fake.specs) != 0 {
			t.Errorf("%s: err = %v, sandbox runs = %d", name, err, len(fake.specs))
		}
	}
}

func TestRunnerFailuresAreErrors(t *testing.T) {
	for name, fake := range map[string]*fakeSandbox{
		"sandbox error": {err: errors.New("docker unavailable")},
		"timeout":       {result: sandbox.Result{TimedOut: true}},
		"exit code":     {result: sandbox.Result{ExitCode: 1, Stderr: []byte("portscan: bad job")}},
		"truncated":     {result: sandbox.Result{Truncated: true}},
		"not json":      {result: sandbox.Result{Stdout: []byte("oops")}},
	} {
		if _, err := newRunner(fake).Scan(context.Background()); err == nil {
			t.Errorf("%s: Scan succeeded", name)
		}
	}
	mutations := map[string]func(*Runner){
		"sandbox": func(r *Runner) { r.Sandbox = nil }, "image": func(r *Runner) { r.Image = "" },
		"gate": func(r *Runner) { r.Gate = "" }, "network": func(r *Runner) { r.Network = sandbox.NetworkNone },
		"timeout": func(r *Runner) { r.Timeout = 0 }, "hosts": func(r *Runner) { r.Hosts = nil },
	}
	for name, mutate := range mutations {
		r := newRunner(&fakeSandbox{})
		mutate(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: Validate succeeded", name)
		}
	}
}
