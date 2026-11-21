package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/bench"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/fix"
	"github.com/dhruv29/vajra/internal/rundiff"
	"github.com/dhruv29/vajra/internal/sandbox"
	"github.com/dhruv29/vajra/internal/sign"
)

// cleanupContainers removes leftover sandbox containers. Tests replace it so
// that they do not need Docker.
var cleanupContainers = func(ctx context.Context) (int, error) {
	return sandbox.NewDocker().Cleanup(ctx)
}

// writeJSON prints a value the way every -json flag does: indented, with a
// trailing newline.
func writeJSON(stdout io.Writer, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	_, err = stdout.Write(append(raw, '\n'))
	return err
}

func runBench(args []string, stdout, stderr io.Writer) (int, error) {
	flags := flag.NewFlagSet("bench", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data", "", "data directory (required)")
	runID := flags.String("run", "", "ID of the run to score (required)")
	keyPath := flags.String("key", "", "answer key: the issues the target is known to have, and decoys (required)")
	minPrecision := flags.Float64("min-precision", 0, "exit with status 3 when precision is below this, from 0 to 1")
	minRecall := flags.Float64("min-recall", 0, "exit with status 3 when recall is below this, from 0 to 1")
	asJSON := flags.Bool("json", false, "print the score as JSON")
	unreviewed := flags.Bool("unreviewed", false,
		"also count findings that passed every check but were not reviewed (a run without a model)")
	if err := flags.Parse(args); err != nil {
		return exitUsage, err
	}
	if *dataDir == "" || *runID == "" || *keyPath == "" {
		return exitUsage, errors.New("-data, -run and -key are required")
	}
	if !isRatio(*minPrecision) || !isRatio(*minRecall) {
		return exitUsage, errors.New("-min-precision and -min-recall must be between 0 and 1")
	}
	keyFile, err := os.Open(*keyPath)
	if err != nil {
		return exitError, err
	}
	defer keyFile.Close()
	key, err := bench.ParseKey(keyFile)
	if err != nil {
		return exitError, err
	}
	run, err := loadRun(*dataDir, *runID)
	if err != nil {
		return exitError, err
	}
	score := bench.EvaluateWith(key, run.Report.Findings, bench.Options{CountUnreviewed: *unreviewed})
	if *asJSON {
		if err := writeJSON(stdout, score); err != nil {
			return exitError, err
		}
	} else {
		fmt.Fprint(stdout, score.Text())
	}
	if !score.Passed(*minPrecision, *minRecall) {
		fmt.Fprintf(stderr, "vajra: the score is below the required precision %.2f or recall %.2f\n", *minPrecision, *minRecall)
		return exitConfirmed, nil
	}
	return exitOK, nil
}

func isRatio(v float64) bool {
	return v >= 0 && v <= 1
}

func runDiff(args []string, stdout, stderr io.Writer) (int, error) {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data", "", "data directory (required)")
	baseID := flags.String("base", "", "ID of the earlier run (required)")
	headID := flags.String("head", "", "ID of the later run (required)")
	format := flags.String("format", "md", "md or json")
	failOnNew := flags.Bool("fail-on-new", false, "exit with status 3 when the later run has findings the earlier one did not")
	if err := flags.Parse(args); err != nil {
		return exitUsage, err
	}
	if *dataDir == "" || *baseID == "" || *headID == "" {
		return exitUsage, errors.New("-data, -base and -head are required")
	}
	if *format != "md" && *format != "json" {
		return exitUsage, fmt.Errorf("unknown diff format %q: use md or json", *format)
	}
	base, err := loadRun(*dataDir, *baseID)
	if err != nil {
		return exitError, err
	}
	head, err := loadRun(*dataDir, *headID)
	if err != nil {
		return exitError, err
	}
	diff := rundiff.Compare(base, head)
	if *format == "json" {
		if err := writeJSON(stdout, diff); err != nil {
			return exitError, err
		}
	} else {
		fmt.Fprint(stdout, diff.Markdown())
	}
	if *failOnNew && diff.HasNew() {
		return exitConfirmed, nil
	}
	return exitOK, nil
}

func runKeygen(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	privatePath := flags.String("private", "", "where to write the private key; an existing file is never overwritten (required)")
	publicPath := flags.String("public", "", "where to write the public key, the half to hand out (required)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *privatePath == "" || *publicPath == "" {
		return errors.New("-private and -public are required")
	}
	if err := sign.GenerateKey(*privatePath, *publicPath); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "wrote the private key to %s and the public key to %s\n", *privatePath, *publicPath)
	fmt.Fprintln(stdout, "keep the private key safe: anyone who has it can sign reports as you, and it cannot be recovered if lost")
	return nil
}

func runSign(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inPath := flags.String("in", "", "file to sign, such as a report (required)")
	keyPath := flags.String("key", "", "private key made by keygen (required)")
	outPath := flags.String("out", "", "where to write the signature (default: the -in path with .sig added)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *keyPath == "" {
		return errors.New("-in and -key are required")
	}
	if *outPath == "" {
		*outPath = *inPath + ".sig"
	}
	document, err := os.ReadFile(*inPath)
	if err != nil {
		return err
	}
	signature, err := sign.Sign(document, *keyPath, time.Now())
	if err != nil {
		return err
	}
	raw, err := signature.Marshal()
	if err != nil {
		return err
	}
	if err := writePrivate(*outPath, raw); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %s with key %s; the signature is in %s\n", *inPath, signature.KeyID, *outPath)
	return nil
}

func runVerifySignature(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify-signature", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inPath := flags.String("in", "", "file that was signed (required)")
	sigPath := flags.String("sig", "", "signature written by sign (required)")
	publicPath := flags.String("public", "", "public key of the signer, obtained from a source you trust (required)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *sigPath == "" || *publicPath == "" {
		return errors.New("-in, -sig and -public are required")
	}
	document, err := os.ReadFile(*inPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*sigPath)
	if err != nil {
		return err
	}
	signature, err := sign.ParseSignature(raw)
	if err != nil {
		return err
	}
	if err := sign.Verify(document, signature, *publicPath); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signature is valid (key %s, signed %s)\n", signature.KeyID, signature.SignedAt.Format(time.RFC3339))
	return nil
}

func runFix(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	flags := flag.NewFlagSet("fix", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to the run configuration (required)")
	dataDir := flags.String("data", "", "data directory (required)")
	runID := flags.String("run", "", "ID of the run that holds the finding (required)")
	findingID := flags.String("finding", "", "ID of the code finding to fix (required)")
	outPath := flags.String("out", "", "write the patch here instead of standard output; exit status 3 means the patch was not verified")
	if err := flags.Parse(args); err != nil {
		return exitUsage, err
	}
	if *configPath == "" || *dataDir == "" || *runID == "" || *findingID == "" {
		return exitUsage, errors.New("-config, -data, -run and -finding are required")
	}
	cfg, _, err := config.Load(*configPath)
	if err != nil {
		return exitError, err
	}
	run, err := loadRun(*dataDir, *runID)
	if err != nil {
		return exitError, err
	}
	result, err := app.Fix(ctx, cfg, newDeps(), run, *findingID)
	if err != nil {
		return exitError, err
	}
	return reportFix(result, *outPath, stdout, stderr)
}

// reportFix prints the outcome of a fix attempt. The verdict goes to standard
// error so that standard output carries only the patch and can be piped into
// a tool that applies it. An unverified patch is still written, for a person
// to finish, but the exit status says it cannot be trusted as it is.
func reportFix(result fix.Result, outPath string, stdout, stderr io.Writer) (int, error) {
	verdict := "not verified"
	if result.Verified {
		verdict = "verified"
	}
	fmt.Fprintf(stderr, "vajra: fix for %s in %s: %s\n", result.FindingID, result.File, verdict)
	fmt.Fprintf(stderr, "vajra: reason: %s\n", printable(result.Reason))
	if result.Explanation != "" {
		fmt.Fprintf(stderr, "vajra: explanation: %s\n", printable(result.Explanation))
	}
	if result.Patch == "" {
		return exitOK, nil
	}
	if outPath == "" {
		if _, err := io.WriteString(stdout, result.Patch); err != nil {
			return exitError, err
		}
	} else {
		if err := writePrivate(outPath, []byte(result.Patch)); err != nil {
			return exitError, err
		}
		fmt.Fprintf(stderr, "vajra: wrote the patch to %s\n", outPath)
	}
	if !result.Verified {
		return exitConfirmed, nil
	}
	return exitOK, nil
}

func runExposure(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	flags := flag.NewFlagSet("exposure", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data", "", "data directory (required)")
	runID := flags.String("run", "", "ID of a run that recorded its dependencies (required)")
	asJSON := flags.Bool("json", false, "print the new advisories as JSON; exit status 3 means there are some")
	if err := flags.Parse(args); err != nil {
		return exitUsage, err
	}
	if *dataDir == "" || *runID == "" {
		return exitUsage, errors.New("-data and -run are required")
	}
	run, err := loadRun(*dataDir, *runID)
	if err != nil {
		return exitError, err
	}
	fresh, err := app.Exposure(ctx, newDeps(), run)
	if err != nil {
		return exitError, err
	}
	switch {
	case *asJSON:
		if err := writeJSON(stdout, fresh); err != nil {
			return exitError, err
		}
	case len(fresh) == 0:
		fmt.Fprintln(stdout, "no new advisories since this run")
	default:
		for _, f := range fresh {
			fmt.Fprintf(stdout, "%-8s %s (%s)\n", f.Severity, printable(f.Title), printable(f.Target))
		}
	}
	if len(fresh) > 0 {
		return exitConfirmed, nil
	}
	return exitOK, nil
}

func runCleanup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	removed, err := cleanupContainers(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "removed %d leftover sandbox containers\n", removed)
	return nil
}

// runStop asks a running scan to stop its autonomous explorer. The scan may
// be in another terminal or under a scheduler, so the request is a file in
// the data directory they share, which the explorer checks between steps.
func runStop(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("stop", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data", "", "data directory the scan was started with (required)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("-data is required")
	}
	path := stopPath(*dataDir)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, stopFileMode)
	if err != nil {
		return err
	}
	if err := f.Chmod(stopFileMode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "created %s; a scan using this data directory stops its explorer after the current step\n", path)
	return nil
}
