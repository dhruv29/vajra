// Command vajra is the command-line entry point.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/demo"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/portscan"
	"github.com/dhruv29/vajra/internal/probe"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/server"
	"github.com/dhruv29/vajra/internal/store"
)

const (
	exitOK        = 0
	exitError     = 1
	exitUsage     = 2
	exitConfirmed = 3

	reportFileMode = 0o600
	auditFileMode  = 0o600

	serveReadHeaderTimeout = 15 * time.Second
	serveShutdownTimeout   = 2 * time.Second // short: a browser may hold idle connections open
)

const usage = `vajra: security testing that proves its findings

Usage:
  vajra scan   -config run.json [-out report.json] [-data DIR] [-gate-audit FILE] [-fail-on-confirmed]
               [-baseline RUN] [-fail-on-new] [-notify]
  vajra verify -config run.json -in nuclei.jsonl [-out report.json] [-data DIR] [-gate-audit FILE] [-fail-on-confirmed]
               [-baseline RUN] [-fail-on-new] [-notify]
  vajra gate   -config run.json [-listen :3128] [-socks ADDR] [-audit audit.jsonl]
  vajra stop   -data DIR
  vajra pause  -data DIR
  vajra resume -data DIR
  vajra cleanup

  vajra runs     -data DIR
  vajra report   -data DIR -run ID [-format html|md|json] [-out FILE]
  vajra serve    -data DIR [-listen 127.0.0.1:8700]
  vajra diff     -data DIR -base ID -head ID [-format md|json] [-fail-on-new]
  vajra bench    -data DIR -run ID -key FILE [-min-precision 0.9] [-min-recall 0.9] [-json]
  vajra exposure -data DIR -run ID [-json]
  vajra fix      -config run.json -data DIR -run ID -finding ID [-out FILE.patch]
  vajra demo     -data DIR

  vajra keygen           -private FILE -public FILE
  vajra sign             -in FILE -key PRIVATE [-out FILE.sig]
  vajra verify-signature -in FILE -sig FILE.sig -public PUBLIC

  scan      run the scanner against the configured targets, then verify each result
  verify    verify scanner output saved earlier
  gate      run the egress proxy that enforces the scope for task containers
  stop      tell a running scan's autonomous explorer to stop after its current step
  pause     make the explorer wait after its current step
  resume    let a paused explorer continue
  cleanup   remove sandbox containers left behind by an interrupted run

  runs      list the runs saved in a data directory
  report    render a saved run, with the blast radius of each finding
  serve     open the web interface over saved runs, on this machine only
  diff      show what changed between two saved runs
  bench     score a saved run against an answer key of known issues and decoys
  exposure  check a saved run's dependencies for advisories published since
  fix       propose a patch for one code finding and check it against the rule
  demo      save a sample run, to explore the reports and the interface

  keygen            create a key pair for signing reports
  sign              sign a file, such as a report, with a private key
  verify-signature  check that a file is the one that was signed

With -data, scan and verify also save the run so that it can be reported on.
-gate-audit adds the gate's audit log, which shows what the run touched.
-baseline compares the new run with an earlier one; -notify posts a summary
of it to the configured webhook. diff, bench, exposure and fix exit with
status 3 when they have something to act on; see each command's -h.
`

// newDeps builds the real dependencies of a run. Tests replace it so that
// they do not need Docker.
var newDeps = func() app.Deps {
	docker := sandbox.NewDocker()
	return app.Deps{Runner: docker, CheckNetwork: docker.RequireInternalNetwork, Getenv: os.Getenv}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWith(ctx, args, os.Stdin, stdout, stderr)
}

func runWith(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	var err error
	code := exitOK
	switch args[0] {
	case "scan", "verify":
		code, err = runReport(ctx, args[0], args[1:], stdin, stdout, stderr)
	case "gate":
		err = runGate(ctx, args[1:], stderr)
	case "runs":
		err = runList(args[1:], stdout, stderr)
	case "report":
		err = runRender(args[1:], stdout, stderr)
	case "serve":
		err = runServe(ctx, args[1:], stderr)
	case "demo":
		err = runDemo(args[1:], stdout, stderr)
	case "pause":
		err = runPause(args[1:], stdout, stderr)
	case "resume":
		err = runResume(args[1:], stdout, stderr)
	case "stop":
		err = runStop(args[1:], stdout, stderr)
	case "cleanup":
		err = runCleanup(ctx, args[1:], stdout, stderr)
	case "diff":
		code, err = runDiff(args[1:], stdout, stderr)
	case "bench":
		code, err = runBench(args[1:], stdout, stderr)
	case "exposure":
		code, err = runExposure(ctx, args[1:], stdout, stderr)
	case "fix":
		code, err = runFix(ctx, args[1:], stdout, stderr)
	case "keygen":
		err = runKeygen(args[1:], stdout, stderr)
	case "sign":
		err = runSign(args[1:], stdout, stderr)
	case "verify-signature":
		err = runVerifySignature(args[1:], stdout, stderr)
	case "probe":
		err = runProbe(ctx, args[1:], stdin, stdout, stderr)
	case "portscan":
		// Like probe, this runs inside a sandbox container, started by a scan.
		err = portscan.RunJob(ctx, stdin, stdout)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "vajra: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitUsage
	}
	if err != nil {
		fmt.Fprintf(stderr, "vajra: %v\n", err)
		return exitError
	}
	return code
}

func runReport(ctx context.Context, command string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to the run configuration (required)")
	inPath := flags.String("in", "", "scanner output to verify (verify only)")
	outPath := flags.String("out", "", "write the report here instead of standard output")
	failOnConfirmed := flags.Bool("fail-on-confirmed", false, "exit with status 3 when any finding is confirmed")
	dataDir := flags.String("data", "", "also save the run in this data directory")
	gateAudit := flags.String("gate-audit", "", "the gate's audit log, to record what the run touched (needs -data)")
	baselineID := flags.String("baseline", "", "ID of an earlier saved run; what changed since is printed to standard error (needs -data)")
	failOnNew := flags.Bool("fail-on-new", false, "exit with status 3 when the run has findings the baseline did not (needs -baseline)")
	notify := flags.Bool("notify", false, "post a summary of the saved run to the configured webhook (needs -data)")
	if err := flags.Parse(args); err != nil {
		return exitUsage, err
	}
	if err := checkSaveFlags(*dataDir, *gateAudit, *baselineID, *failOnNew, *notify); err != nil {
		return exitUsage, err
	}
	if *configPath == "" {
		return exitUsage, errors.New("-config is required")
	}
	cfg, policy, err := config.Load(*configPath)
	if err != nil {
		return exitError, err
	}
	// Loaded before anything runs: a mistyped ID should not cost a whole scan.
	baseline, err := loadBaseline(*dataDir, *baselineID)
	if err != nil {
		return exitError, err
	}
	deps := newDeps()
	started := time.Now()

	var report app.Report
	if command == "verify" {
		if *inPath == "" {
			return exitUsage, errors.New("-in is required for verify")
		}
		in, err := os.Open(*inPath)
		if err != nil {
			return exitError, err
		}
		defer in.Close()
		report, err = app.VerifyOutput(ctx, cfg, policy, deps, in)
		if err != nil {
			return exitError, err
		}
	} else {
		deps, err = withOperatorControls(deps, cfg, *dataDir, stdin, stderr)
		if err != nil {
			return exitError, err
		}
		report, err = app.Scan(ctx, cfg, policy, deps)
		if err != nil {
			return exitError, err
		}
	}

	// The findings are written first. Saving the run also reads the gate's
	// audit log, and a problem there must not cost the results of a scan
	// that has already been paid for.
	if *outPath != "" || *dataDir == "" {
		if err := writeReport(report, *outPath, stdout); err != nil {
			return exitError, err
		}
	}
	var saved *record.Run
	if *dataDir != "" {
		run, err := saveRun(report, cfg, *dataDir, *gateAudit, started)
		if err != nil {
			return exitError, err
		}
		fmt.Fprintf(stderr, "vajra: saved run %s\n", run.ID)
		saved = &run
	}
	fmt.Fprintf(stderr, "vajra: %d confirmed, %d unconfirmed, %d refuted, %d out of scope\n",
		report.Summary[finding.Confirmed], report.Summary[finding.Unconfirmed],
		report.Summary[finding.Refuted], report.Summary[finding.OutOfScope])
	if saved != nil && *notify {
		notifyRun(ctx, cfg, deps, *saved, stderr)
	}
	hasNew := saved != nil && baseline != nil && printChanges(*baseline, *saved, stderr)
	if *failOnConfirmed && report.Summary[finding.Confirmed] > 0 {
		return exitConfirmed, nil
	}
	if *failOnNew && hasNew {
		return exitConfirmed, nil
	}
	return exitOK, nil
}

func writeReport(report app.Report, path string, stdout io.Writer) error {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	raw = append(raw, '\n')
	if path == "" {
		_, err = stdout.Write(raw)
		return err
	}
	return writePrivate(path, raw)
}

func runGate(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("gate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to the run configuration (required)")
	listen := flags.String("listen", "127.0.0.1:3128", "address the proxy listens on; it has no authentication, so expose it only to the task network")
	auditPath := flags.String("audit", "", "append the audit log here instead of standard error")
	socksAddr := flags.String("socks", "", "also serve SOCKS5 on this address, for tools that speak raw TCP; off when empty, and as unauthenticated as -listen")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("-config is required")
	}
	_, policy, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.New("this configuration has no scope, so there is nothing for a gate to enforce")
	}
	audit := stderr
	if *auditPath != "" {
		f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, auditFileMode)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := f.Chmod(auditFileMode); err != nil {
			return err
		}
		audit = f
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	// Closing twice is harmless, and this covers every way out, including the
	// ones where the gate never started serving.
	defer listener.Close()
	fmt.Fprintf(stderr, "vajra: egress gate listening on %s\n", listener.Addr())
	// A nil interface, not a nil *net.TCPListener: ServeGate tests for nil.
	var socks net.Listener
	if *socksAddr != "" {
		if socks, err = net.Listen("tcp", *socksAddr); err != nil {
			return err
		}
		defer socks.Close()
		fmt.Fprintf(stderr, "vajra: egress gate listening for SOCKS5 on %s\n", socks.Addr())
	}
	return app.ServeGate(ctx, policy, listener, socks, audit)
}

func saveRun(report app.Report, cfg config.Config, dataDir, auditPath string, started time.Time) (record.Run, error) {
	var audit io.Reader
	if auditPath != "" {
		f, err := os.Open(auditPath)
		if err != nil {
			return record.Run{}, err
		}
		defer f.Close()
		audit = f
	}
	return app.Record(report, cfg, audit, started, dataDir, time.Now())
}

func runList(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("runs", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data", "", "data directory (required)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("-data is required")
	}
	st, err := store.Open(*dataDir)
	if err != nil {
		return err
	}
	runs, err := st.List()
	if err != nil {
		return err
	}
	if len(runs) == 0 {
		fmt.Fprintln(stdout, "no saved runs")
		return nil
	}
	fmt.Fprintf(stdout, "%-26s %-10s %-12s %-6s %s\n", "RUN", "CONFIRMED", "UNCONFIRMED", "TOP", "TARGETS")
	for _, r := range runs {
		fmt.Fprintf(stdout, "%-26s %-10d %-12d %-6d %s\n", r.ID, r.Counts[finding.Confirmed],
			r.Counts[finding.Unconfirmed], r.TopScore, strings.Join(r.Targets, ", "))
	}
	return nil
}

func runRender(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data", "", "data directory (required)")
	runID := flags.String("run", "", "run ID, as printed by scan or listed by runs (required)")
	format := flags.String("format", "html", "html, md or json")
	outPath := flags.String("out", "", "write here instead of standard output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *runID == "" {
		return errors.New("-data and -run are required")
	}
	st, err := store.Open(*dataDir)
	if err != nil {
		return err
	}
	run, err := st.Get(*runID)
	if err != nil {
		return err
	}
	rendered, err := app.Render(run, *format)
	if err != nil {
		return err
	}
	if *outPath == "" {
		_, err = stdout.Write(rendered)
		return err
	}
	return writePrivate(*outPath, rendered)
}

// writePrivate writes a file that only its owner can read. Reports hold
// captured requests and responses. The mode is set explicitly because writing
// over an existing file would otherwise keep that file's looser mode.
func writePrivate(path string, content []byte) error {
	if err := os.WriteFile(path, content, reportFileMode); err != nil {
		return err
	}
	return os.Chmod(path, reportFileMode)
}

func runServe(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data", "", "data directory (required)")
	listen := flags.String("listen", "127.0.0.1:8700", "loopback address to listen on")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("-data is required")
	}
	if _, err := server.LoopbackAddr(*listen); err != nil {
		return err
	}
	st, err := store.Open(*dataDir)
	if err != nil {
		return err
	}
	token, err := server.NewToken()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	// Derived from the bound address, so "-listen 127.0.0.1:0" works.
	hosts, err := server.LoopbackAddr(listener.Addr().String())
	if err != nil {
		listener.Close()
		return err
	}
	handler, err := server.New(st, token, hosts)
	if err != nil {
		listener.Close()
		return err
	}
	fmt.Fprintf(stderr, "vajra: open http://%s/#token=%s\n", listener.Addr(), token)
	return serveUntilDone(ctx, listener, handler)
}

func serveUntilDone(ctx context.Context, listener net.Listener, handler http.Handler) error {
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: serveReadHeaderTimeout}
	stopped := make(chan error, 1)
	go func() { stopped <- srv.Serve(listener) }()
	select {
	case err := <-stopped:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), serveShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return srv.Close()
		}
		return nil
	}
}

func runDemo(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data", "", "data directory (required)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("-data is required")
	}
	st, err := store.Open(*dataDir)
	if err != nil {
		return err
	}
	now := time.Now()
	id, err := store.NewID(now)
	if err != nil {
		return err
	}
	run, err := demo.Run(id, now)
	if err != nil {
		return err
	}
	if err := st.Save(run); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "saved sample run %s; view it with: vajra serve -data %s\n", id, *dataDir)
	return nil
}

// runProbe is not meant to be typed by a person. The orchestrator starts it
// inside a sandbox container on the task network, so that Vajra's own
// requests pass through the egress gate like any other tool's.
func runProbe(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	proxy := flags.String("proxy", "", "the egress gate, as http://host:port (required)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *proxy == "" {
		return errors.New("-proxy is required")
	}
	return probe.Run(ctx, *proxy, stdin, stdout)
}
