package sandbox

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func validSpec() Spec {
	return Spec{
		Image:   "vajra-nuclei:local",
		Argv:    []string{"-u", "https://app.test"},
		Network: "vajra-task-net",
		Timeout: time.Minute,
	}
}

func TestDockerArgsLockTheContainerDown(t *testing.T) {
	spec := validSpec()
	spec.Env = map[string]string{"HTTPS_PROXY": "http://gate:3128", "A": "1"}
	spec.Mounts = []Mount{{Source: "/srv/src", Target: "/src"}, {Source: "/srv/out", Target: "/out", Writable: true}}
	spec.Workdir = "/src"

	args, err := DockerArgs(spec, "vajra-abc123")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"run --rm --name vajra-abc123",
		"--network vajra-task-net",
		"--read-only",
		"--cap-drop ALL",
		"--security-opt no-new-privileges",
		"--pids-limit 256",
		"--memory 1024m --memory-swap 1024m",
		"--user 65534:65534",
		"--workdir /src",
		"--mount type=bind,source=/srv/src,target=/src,readonly",
		"--mount type=bind,source=/srv/out,target=/out --env",
		"--label vajra.sandbox=1",
		"--env A=1 --env HTTPS_PROXY=http://gate:3128",
		"vajra-nuclei:local -u https://app.test",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args are missing %q\n got: %s", want, joined)
		}
	}
	for _, banned := range []string{"--privileged", "--cap-add", "--network host", "--pid ", "--pid=", "docker.sock"} {
		if strings.Contains(joined, banned) {
			t.Errorf("args contain %q", banned)
		}
	}
	if imageAt := slices.Index(args, "vajra-nuclei:local"); !slices.Equal(args[imageAt+1:], spec.Argv) {
		t.Errorf("tool arguments were altered: %v", args[imageAt+1:])
	}
}

func TestDockerArgsKeepHostileToolArgumentsAsData(t *testing.T) {
	spec := validSpec()
	spec.Argv = []string{"-u", "https://app.test/?q=$(id);rm -rf /", "--privileged"}

	args, err := DockerArgs(spec, "vajra-abc123")
	if err != nil {
		t.Fatal(err)
	}

	imageAt := slices.Index(args, spec.Image)
	if slices.Contains(args[:imageAt], "--privileged") {
		t.Fatal("a tool argument became a docker flag")
	}
	if !slices.Equal(args[imageAt+1:], spec.Argv) {
		t.Fatalf("tool arguments were altered: %v", args[imageAt+1:])
	}
}

func TestValidateRejectsUnsafeSpecs(t *testing.T) {
	mutations := map[string]func(*Spec){
		"no image":                    func(s *Spec) { s.Image = "" },
		"image looks like a flag":     func(s *Spec) { s.Image = "--privileged" },
		"nothing to run":              func(s *Spec) { s.Argv = nil },
		"no timeout":                  func(s *Spec) { s.Timeout = 0 },
		"no network":                  func(s *Spec) { s.Network = "" },
		"host network":                func(s *Spec) { s.Network = "host" },
		"default bridge":              func(s *Spec) { s.Network = "bridge" },
		"another container's network": func(s *Spec) { s.Network = "container:db" },
		"root user":                   func(s *Spec) { s.User = "0:0" },
		"named user":                  func(s *Spec) { s.User = "root" },
		"bad env name":                func(s *Spec) { s.Env = map[string]string{"A=B": "1"} },
		"negative memory":             func(s *Spec) { s.MemoryMB = -1 },
		"relative workdir":            func(s *Spec) { s.Workdir = "src" },
		"relative mount source":       func(s *Spec) { s.Mounts = []Mount{{Source: "src", Target: "/src"}} },
		"unclean mount source":        func(s *Spec) { s.Mounts = []Mount{{Source: "/srv/../etc", Target: "/src"}} },
		"host root mount":             func(s *Spec) { s.Mounts = []Mount{{Source: "/", Target: "/host"}} },
		"host etc mount":              func(s *Spec) { s.Mounts = []Mount{{Source: "/etc/ssh", Target: "/x"}} },
		"docker data mount":           func(s *Spec) { s.Mounts = []Mount{{Source: "/var/lib/docker/volumes", Target: "/x"}} },
		"root home mount":             func(s *Spec) { s.Mounts = []Mount{{Source: "/root/.ssh", Target: "/x"}} },
		"whole home tree mount":       func(s *Spec) { s.Mounts = []Mount{{Source: "/home", Target: "/x"}} },
		"whole Users tree mount":      func(s *Spec) { s.Mounts = []Mount{{Source: "/Users", Target: "/x"}} },
		"whole var mount":             func(s *Spec) { s.Mounts = []Mount{{Source: "/var", Target: "/x"}} },
		"docker socket mount":         func(s *Spec) { s.Mounts = []Mount{{Source: "/var/run/docker.sock", Target: "/d.sock"}} },
		"relocated docker socket":     func(s *Spec) { s.Mounts = []Mount{{Source: "/home/u/.docker/run/docker.sock", Target: "/d.sock"}} },
		"mount over root":             func(s *Spec) { s.Mounts = []Mount{{Source: "/srv/src", Target: "/"}} },
		"mount option injection":      func(s *Spec) { s.Mounts = []Mount{{Source: "/srv/a,readonly=false", Target: "/src"}} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			spec := validSpec()
			mutate(&spec)
			if _, err := DockerArgs(spec, "vajra-abc123"); err == nil {
				t.Fatal("DockerArgs succeeded; want an error")
			}
		})
	}
}

func TestDockerArgsAllowNoNetworkAndRejectBadNames(t *testing.T) {
	spec := validSpec()
	spec.Network = NetworkNone
	if _, err := DockerArgs(spec, "vajra-abc123"); err != nil {
		t.Fatalf("network none: %v", err)
	}
	if _, err := DockerArgs(spec, "--rm"); err == nil {
		t.Fatal("a flag-like container name was accepted")
	}
}

func TestProxyEnvPointsEverySchemeAtTheGate(t *testing.T) {
	env := ProxyEnv("http://gate:3128")
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if env[key] != "http://gate:3128" {
			t.Errorf("%s = %q", key, env[key])
		}
	}
	if env["NO_PROXY"] != "" || env["no_proxy"] != "" {
		t.Error("a proxy exemption was set")
	}
}

// fakeDocker stands in for the docker CLI.
type fakeDocker struct {
	stdin  string
	calls  [][]string
	stdout string
	code   int
	err    error
	block  bool
}

func (f *fakeDocker) exec(ctx context.Context, args []string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
	f.calls = append(f.calls, args)
	if stdin != nil {
		raw, _ := io.ReadAll(stdin)
		f.stdin = string(raw)
	}
	if args[0] == "kill" {
		return 0, nil
	}
	if f.block {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	_, _ = io.WriteString(stdout, f.stdout)
	return f.code, f.err
}

func TestRunReturnsOutputAndExitCode(t *testing.T) {
	fake := &fakeDocker{stdout: "result line\n", code: 2}
	runner := &Docker{exec: fake.exec}

	result, err := runner.Run(context.Background(), validSpec())

	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 2 || string(result.Stdout) != "result line\n" || result.TimedOut || result.Truncated {
		t.Fatalf("result = %+v", result)
	}
	name := fake.calls[0][slices.Index(fake.calls[0], "--name")+1]
	if !strings.HasPrefix(name, "vajra-") || len(name) != len("vajra-")+2*nameRandBytes {
		t.Fatalf("container name = %q", name)
	}
}

func TestRunStopsTheContainerOnTimeout(t *testing.T) {
	fake := &fakeDocker{block: true}
	runner := &Docker{exec: fake.exec}
	spec := validSpec()
	spec.Timeout = 20 * time.Millisecond

	result, err := runner.Run(context.Background(), spec)

	if err != nil || !result.TimedOut {
		t.Fatalf("result = %+v, err = %v; want a timeout result", result, err)
	}
	last := fake.calls[len(fake.calls)-1]
	name := fake.calls[0][slices.Index(fake.calls[0], "--name")+1]
	if len(last) != 2 || last[0] != "kill" || last[1] != name {
		t.Fatalf("last docker call = %v; want kill %s", last, name)
	}
}

func TestRunStopsTheContainerWhenTheCallerCancels(t *testing.T) {
	fake := &fakeDocker{block: true}
	runner := &Docker{exec: fake.exec}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)

	result, err := runner.Run(ctx, validSpec())

	if !errors.Is(err, context.Canceled) || result.TimedOut {
		t.Fatalf("result = %+v, err = %v; want context.Canceled", result, err)
	}
	if last := fake.calls[len(fake.calls)-1]; last[0] != "kill" {
		t.Fatalf("last docker call = %v; want kill", last)
	}
}

func TestRunCapsOutput(t *testing.T) {
	fake := &fakeDocker{stdout: strings.Repeat("x", 100)}
	runner := &Docker{exec: fake.exec}
	spec := validSpec()
	spec.OutputCap = 10

	result, err := runner.Run(context.Background(), spec)

	if err != nil || len(result.Stdout) != 10 || !result.Truncated {
		t.Fatalf("len = %d, truncated = %v, err = %v", len(result.Stdout), result.Truncated, err)
	}
}

func TestRunReportsCLIFailureAndInvalidSpecs(t *testing.T) {
	fake := &fakeDocker{err: errors.New("docker: not found"), code: -1}
	runner := &Docker{exec: fake.exec}
	if _, err := runner.Run(context.Background(), validSpec()); err == nil {
		t.Error("a CLI failure was not reported")
	}

	bad := validSpec()
	bad.Network = "host"
	if _, err := runner.Run(context.Background(), bad); err == nil {
		t.Error("an invalid spec was run")
	}
	if len(fake.calls) != 1 {
		t.Errorf("docker was called %d times; the invalid spec must not reach it", len(fake.calls))
	}
}

func TestCappedBufferKeepsOnlyTheFirstBytes(t *testing.T) {
	c := &cappedBuffer{limit: 5}
	for _, chunk := range []string{"abc", "defg", "hij"} {
		if n, err := c.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", chunk, n, err)
		}
	}
	if c.buf.String() != "abcde" || !c.truncated {
		t.Fatalf("buffer = %q, truncated = %v", c.buf.String(), c.truncated)
	}
}

func TestNewDockerUsesTheRealCLI(t *testing.T) {
	if NewDocker().exec == nil {
		t.Fatal("no exec function")
	}
}

func TestProjectDirectoriesUnderHomeCanBeMounted(t *testing.T) {
	for _, source := range []string{"/home/dev/project", "/Users/dev/project", "/srv/app", "/var/folders/ab/T/tmp.x/src"} {
		spec := validSpec()
		spec.Mounts = []Mount{{Source: source, Target: "/src"}}
		if _, err := DockerArgs(spec, "vajra-abc123"); err != nil {
			t.Errorf("%s: %v", source, err)
		}
	}
}

// inspectDocker answers "docker network inspect" with fixed output.
type inspectDocker struct {
	output string
	code   int
	err    error
	calls  [][]string
}

func (f *inspectDocker) exec(_ context.Context, args []string, _ io.Reader, stdout, _ io.Writer) (int, error) {
	f.calls = append(f.calls, args)
	_, _ = io.WriteString(stdout, f.output)
	return f.code, f.err
}

func TestRequireInternalNetwork(t *testing.T) {
	cases := []struct {
		name    string
		network string
		fake    inspectDocker
		ok      bool
	}{
		{"internal network", "vajra-task-net", inspectDocker{output: "true vajra-task-net\n"}, true},
		{"ordinary network", "vajra-task-net", inspectDocker{output: "false vajra-task-net\n"}, false},
		{"id prefix of another network", "0a1b2c", inspectDocker{output: "true some-other-net\n"}, false},
		{"id of the bridge network", "f00dfeed", inspectDocker{output: "false bridge\n"}, false},
		{"missing network", "vajra-task-net", inspectDocker{code: 1}, false},
		{"docker unavailable", "vajra-task-net", inspectDocker{err: errors.New("no docker"), code: -1}, false},
		{"host network", "host", inspectDocker{output: "true host\n"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := tc.fake
			err := (&Docker{exec: fake.exec}).RequireInternalNetwork(context.Background(), tc.network)
			if tc.ok != (err == nil) {
				t.Fatalf("err = %v; want ok=%v", err, tc.ok)
			}
		})
	}
	none := &inspectDocker{}
	if err := (&Docker{exec: none.exec}).RequireInternalNetwork(context.Background(), NetworkNone); err != nil || len(none.calls) != 0 {
		t.Fatalf("network none: err = %v, docker calls = %d", err, len(none.calls))
	}
}

func TestRunPassesStandardInputOnlyWhenGiven(t *testing.T) {
	fake := &fakeDocker{}
	runner := &Docker{exec: fake.exec}
	spec := validSpec()
	spec.Stdin = []byte(`{"requests":[]}`)

	if _, err := runner.Run(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if fake.stdin != `{"requests":[]}` || !slices.Contains(fake.calls[0], "--interactive") {
		t.Fatalf("stdin = %q, args = %v", fake.stdin, fake.calls[0])
	}

	plain := &fakeDocker{}
	if _, err := (&Docker{exec: plain.exec}).Run(context.Background(), validSpec()); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(plain.calls[0], "--interactive") {
		t.Fatal("standard input was left open for a tool that was given none")
	}
}

// cleanupDocker answers "ps" with ids and records the "rm" call.
type cleanupDocker struct {
	ids    string
	psCode int
	rmCode int
	calls  [][]string
}

func (f *cleanupDocker) exec(_ context.Context, args []string, _ io.Reader, stdout, _ io.Writer) (int, error) {
	f.calls = append(f.calls, args)
	if args[0] == "ps" {
		_, _ = io.WriteString(stdout, f.ids)
		return f.psCode, nil
	}
	return f.rmCode, nil
}

func TestCleanupRemovesOnlyLabelledContainers(t *testing.T) {
	fake := &cleanupDocker{ids: "abc123\ndef456\n"}

	removed, err := (&Docker{exec: fake.exec}).Cleanup(context.Background())

	if err != nil || removed != 2 {
		t.Fatalf("removed = %d, err = %v", removed, err)
	}
	if got := strings.Join(fake.calls[0], " "); got != "ps --all --quiet --filter label=vajra.sandbox=1" {
		t.Fatalf("list call = %q", got)
	}
	if got := strings.Join(fake.calls[1], " "); got != "rm --force abc123 def456" {
		t.Fatalf("remove call = %q", got)
	}

	none := &cleanupDocker{}
	if removed, err := (&Docker{exec: none.exec}).Cleanup(context.Background()); err != nil || removed != 0 || len(none.calls) != 1 {
		t.Fatalf("nothing to remove: removed = %d, err = %v, calls = %d", removed, err, len(none.calls))
	}
	for name, fake := range map[string]*cleanupDocker{"list fails": {psCode: 1}, "remove fails": {ids: "abc", rmCode: 1}} {
		if _, err := (&Docker{exec: fake.exec}).Cleanup(context.Background()); err == nil {
			t.Errorf("%s: Cleanup succeeded", name)
		}
	}
}
