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
	"syscall"

	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/sandbox"
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
  vajra scan   -config run.json [-out report.json] [-fail-on-confirmed]
  vajra verify -config run.json -in nuclei.jsonl [-out report.json] [-fail-on-confirmed]
  vajra gate   -config run.json [-listen :3128] [-audit audit.jsonl]

  scan    run the scanner against the configured targets, then verify each result
  verify  verify scanner output saved earlier
  gate    run the egress proxy that enforces the scope for task containers
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
	if err := flags.Parse(args); err != nil {
		return exitUsage, err
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

	if err := writeReport(report, *outPath, stdout); err != nil {
		return exitError, err
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
