// Package sandbox runs one tool invocation in a throwaway, locked-down
// container. There is no unsandboxed mode.
package sandbox

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMemoryMB  = 1024
	defaultPIDs      = 256
	defaultCPUs      = 1.0
	defaultUser      = "65534:65534" // nobody
	defaultOutputCap = 16 << 20
	tmpfsOptions     = "/tmp:rw,noexec,nosuid,nodev,size=128m"

	// NetworkNone gives the container no network at all.
	NetworkNone = "none"
)

// Mount binds a host directory into the container. It is read-only unless
// Writable is set.
type Mount struct {
	Source   string
	Target   string
	Writable bool
}

// Spec describes one sandboxed run.
type Spec struct {
	Image      string
	Entrypoint string
	Argv       []string
	// Network is NetworkNone or the name of a Docker network created with
	// --internal. Host and default bridge networking are refused.
	Network string
	Mounts  []Mount
	// Env is the complete environment of the tool. Nothing is inherited from
	// the host.
	Env      map[string]string
	Workdir  string
	Timeout  time.Duration
	MemoryMB int
	PIDs     int
	CPUs     float64
	User     string
	// OutputCap bounds captured stdout and stderr, each, in bytes.
	OutputCap int
	// Stdin, when not nil, is written to the tool's standard input.
	Stdin []byte
}

// Result is what a sandboxed run produced.
type Result struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	TimedOut  bool
	Truncated bool
}

var (
	imagePattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$`)
	networkPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	envKeyPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	userPattern    = regexp.MustCompile(`^[0-9]+:[0-9]+$`)
)

// forbiddenNetworks would give the tool a route around the egress gate.
var forbiddenNetworks = map[string]bool{"host": true, "bridge": true, "default": true}

// forbiddenMountTrees would hand the tool control of the host: neither they
// nor anything beneath them may be mounted.
var forbiddenMountTrees = []string{"/var/run", "/run", "/etc", "/proc", "/sys", "/dev", "/var/lib/docker", "/root", "/boot"}

// forbiddenMountRoots are too broad to mount whole, though a project
// directory beneath them is fine.
var forbiddenMountRoots = map[string]bool{"/": true, "/var": true, "/usr": true, "/home": true, "/Users": true, "/opt": true, "/srv": true}

const (
	maxID        = 1<<31 - 1
	containerTag = "vajra.sandbox=1"
)

func (s Spec) withDefaults() Spec {
	if s.MemoryMB == 0 {
		s.MemoryMB = defaultMemoryMB
	}
	if s.PIDs == 0 {
		s.PIDs = defaultPIDs
	}
	if s.CPUs == 0 {
		s.CPUs = defaultCPUs
	}
	if s.User == "" {
		s.User = defaultUser
	}
	if s.OutputCap == 0 {
		s.OutputCap = defaultOutputCap
	}
	return s
}

// Validate reports the first reason the spec may not run.
func (s Spec) Validate() error {
	if !imagePattern.MatchString(s.Image) {
		return fmt.Errorf("sandbox: image %q is missing or malformed", s.Image)
	}
	if len(s.Argv) == 0 && s.Entrypoint == "" {
		return errors.New("sandbox: nothing to run")
	}
	if s.Timeout <= 0 {
		return errors.New("sandbox: a timeout is required")
	}
	if err := validateNetwork(s.Network); err != nil {
		return err
	}
	if !nonRootUser(s.User) {
		return fmt.Errorf("sandbox: user %q must be a numeric uid:gid, neither of them 0", s.User)
	}
	if s.MemoryMB < 0 || s.PIDs < 0 || s.CPUs < 0 || s.OutputCap < 0 {
		return errors.New("sandbox: resource limits must not be negative")
	}
	for key := range s.Env {
		if !envKeyPattern.MatchString(key) {
			return fmt.Errorf("sandbox: environment name %q is malformed", key)
		}
	}
	for _, m := range s.Mounts {
		if err := validateMount(m); err != nil {
			return err
		}
	}
	if s.Workdir != "" && !cleanAbs(s.Workdir) {
		return fmt.Errorf("sandbox: workdir %q must be a clean absolute path", s.Workdir)
	}
	return nil
}

// nonRootUser reports whether user is "uid:gid" with both numbers above zero.
// The numbers are parsed, so "00:0" is recognised as root.
func nonRootUser(user string) bool {
	if !userPattern.MatchString(user) {
		return false
	}
	uidText, gidText, _ := strings.Cut(user, ":")
	uid, uidErr := strconv.ParseUint(uidText, 10, 32)
	gid, gidErr := strconv.ParseUint(gidText, 10, 32)
	return uidErr == nil && gidErr == nil && uid > 0 && gid > 0 && uid <= maxID && gid <= maxID
}

func validateNetwork(network string) error {
	if network == "" {
		return errors.New("sandbox: a network is required: use \"none\" or an internal network")
	}
	if forbiddenNetworks[network] || !networkPattern.MatchString(network) {
		return fmt.Errorf("sandbox: network %q is not allowed", network)
	}
	return nil
}

func validateMount(m Mount) error {
	if !cleanAbs(m.Source) || !cleanAbs(m.Target) {
		return fmt.Errorf("sandbox: mount %q -> %q must use clean absolute paths", m.Source, m.Target)
	}
	if strings.ContainsAny(m.Source+m.Target, ",\n\"") {
		return fmt.Errorf("sandbox: mount %q -> %q contains a forbidden character", m.Source, m.Target)
	}
	if m.Target == "/" {
		return errors.New("sandbox: a mount may not replace the container root")
	}
	if forbiddenMountRoots[m.Source] {
		return fmt.Errorf("sandbox: %q is too broad to mount; mount the project directory", m.Source)
	}
	for _, tree := range forbiddenMountTrees {
		if m.Source == tree || strings.HasPrefix(m.Source, tree+"/") {
			return fmt.Errorf("sandbox: mounting %q from the host is not allowed", m.Source)
		}
	}
	if strings.HasSuffix(m.Source, "docker.sock") {
		return errors.New("sandbox: the Docker socket may not be mounted")
	}
	return nil
}

func cleanAbs(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p
}

// DockerArgs returns the arguments for "docker" that run the spec in a
// container named name. The result is passed to exec directly, never to a
// shell.
func DockerArgs(s Spec, name string) ([]string, error) {
	s = s.withDefaults()
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if !networkPattern.MatchString(name) {
		return nil, fmt.Errorf("sandbox: container name %q is malformed", name)
	}
	memory := strconv.Itoa(s.MemoryMB) + "m"
	args := []string{"run"}
	if s.Stdin != nil {
		args = append(args, "--interactive") // keep standard input open
	}
	args = append(args,
		"--rm", "--name", name,
		"--label", containerTag, // lets leftover containers be found and removed
		"--network", s.Network,
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", strconv.Itoa(s.PIDs),
		"--memory", memory,
		"--memory-swap", memory,
		"--cpus", strconv.FormatFloat(s.CPUs, 'f', 2, 64),
		"--user", s.User,
		"--tmpfs", tmpfsOptions,
	)
	if s.Workdir != "" {
		args = append(args, "--workdir", s.Workdir)
	}
	for _, m := range s.Mounts {
		mount := "type=bind,source=" + m.Source + ",target=" + m.Target
		if !m.Writable {
			mount += ",readonly"
		}
		args = append(args, "--mount", mount)
	}
	for _, key := range sortedKeys(s.Env) {
		args = append(args, "--env", key+"="+s.Env[key])
	}
	if s.Entrypoint != "" {
		args = append(args, "--entrypoint", s.Entrypoint)
	}
	args = append(args, s.Image)
	return append(args, s.Argv...), nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ProxyEnv returns the environment that points a tool at the egress proxy.
func ProxyEnv(proxyURL string) map[string]string {
	return map[string]string{
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,
		"NO_PROXY":    "",
		"no_proxy":    "",
	}
}
