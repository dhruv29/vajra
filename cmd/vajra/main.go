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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/store"
)

const (
	exitOK        = 0
	exitError     = 1
	exitUsage     = 2
	exitConfirmed = 3

	reportFileMode = 0o600
	auditFileMode  = 0o600
)

const usage = `vajra: security testing that proves its findings

Usage:
  vajra scan   -config run.json [-out report.json] [-data DIR] [-gate-audit FILE] [-fail-on-confirmed]
  vajra verify -config run.json -in nuclei.jsonl [-out report.json] [-data DIR] [-gate-audit FILE] [-fail-on-confirmed]
  vajra gate   -config run.json [-listen :3128] [-audit audit.jsonl]
  vajra runs   -data DIR
  vajra report -data DIR -run ID [-format html|md|json] [-out FILE]

  scan    run the scanner against the configured targets, then verify each result
  verify  verify scanner output saved earlier
  gate    run the egress proxy that enforces the scope for task containers
  runs    list the runs saved in a data directory
  report  render a saved run, with the blast radius of each finding

With -data, scan and verify also save the run so that it can be reported on.
-gate-audit adds the gate's audit log, which shows what the run touched.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	var err error
	code := exitOK
	switch args[0] {
	case "scan", "verify":
		code, err = runReport(ctx, args[0], args[1:], stdout, stderr)
	case "gate":
		err = runGate(ctx, args[1:], stderr)
	case "runs":
		err = runList(args[1:], stdout, stderr)
	case "report":
		err = runRender(args[1:], stdout, stderr)
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

func runReport(ctx context.Context, command string, args []string, stdout, stderr io.Writer) (int, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to the run configuration (required)")
	inPath := flags.String("in", "", "scanner output to verify (verify only)")
	outPath := flags.String("out", "", "write the report here instead of standard output")
	failOnConfirmed := flags.Bool("fail-on-confirmed", false, "exit with status 3 when any finding is confirmed")
	dataDir := flags.String("data", "", "also save the run in this data directory")
	gateAudit := flags.String("gate-audit", "", "the gate's audit log, to record what the run touched (needs -data)")
	if err := flags.Parse(args); err != nil {
		return exitUsage, err
	}
	if *gateAudit != "" && *dataDir == "" {
		return exitUsage, errors.New("-gate-audit needs -data")
	}
	if *configPath == "" {
		return exitUsage, errors.New("-config is required")
	}
	cfg, policy, err := config.Load(*configPath)
	if err != nil {
		return exitError, err
	}
	deps := app.Deps{Runner: sandbox.NewDocker(), Getenv: os.Getenv}

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
		report, err = app.Scan(ctx, cfg, policy, deps)
		if err != nil {
			return exitError, err
		}
	}

	if *dataDir != "" {
		id, err := saveRun(report, cfg, *dataDir, *gateAudit)
		if err != nil {
			return exitError, err
		}
		fmt.Fprintf(stderr, "vajra: saved run %s\n", id)
	}
	if *outPath != "" || *dataDir == "" {
		if err := writeReport(report, *outPath, stdout); err != nil {
			return exitError, err
		}
	}
	fmt.Fprintf(stderr, "vajra: %d confirmed, %d unconfirmed, %d refuted, %d out of scope\n",
		report.Summary[finding.Confirmed], report.Summary[finding.Unconfirmed],
		report.Summary[finding.Refuted], report.Summary[finding.OutOfScope])
	if *failOnConfirmed && report.Summary[finding.Confirmed] > 0 {
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
	// Reports contain captured requests and responses, so keep them private.
	return os.WriteFile(path, raw, reportFileMode)
}

func runGate(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("gate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to the run configuration (required)")
	listen := flags.String("listen", ":3128", "address the proxy listens on")
	auditPath := flags.String("audit", "", "append the audit log here instead of standard error")
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
	audit := stderr
	if *auditPath != "" {
		f, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, auditFileMode)
		if err != nil {
			return err
		}
		defer f.Close()
		audit = f
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "vajra: egress gate listening on %s\n", listener.Addr())
	return app.ServeGate(ctx, policy, listener, audit)
}

func saveRun(report app.Report, cfg config.Config, dataDir, auditPath string) (string, error) {
	var audit io.Reader
	if auditPath != "" {
		f, err := os.Open(auditPath)
		if err != nil {
			return "", err
		}
		defer f.Close()
		audit = f
	}
	run, err := app.Record(report, cfg, audit, dataDir, time.Now())
	if err != nil {
		return "", err
	}
	return run.ID, nil
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
	return os.WriteFile(*outPath, rendered, reportFileMode)
}
