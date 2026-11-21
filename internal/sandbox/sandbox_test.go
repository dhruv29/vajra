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
	spec.Mounts = []Mount{{Source: "/srv/src", Target: "/src", ReadOnly: true}}
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
	calls  [][]string
	stdout string
	code   int
	err    error
	block  bool
}

func (f *fakeDocker) exec(ctx context.Context, args []string, stdout, _ io.Writer) (int, error) {
	f.calls = append(f.calls, args)
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
