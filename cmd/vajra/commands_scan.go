package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"github.com/dhruv29/vajra/internal/agent"
	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/rundiff"
	"github.com/dhruv29/vajra/internal/store"
)

const (
	// stopFileName is the file in a data directory whose presence tells a
	// running scan's explorer to stop.
	stopFileName = "STOP"
	stopFileMode = 0o600
)

// checkSaveFlags rejects flags that act on the saved run when no run will be
// saved, rather than letting them do nothing.
func checkSaveFlags(dataDir, gateAudit, baselineID string, failOnNew, notify bool) error {
	switch {
	case gateAudit != "" && dataDir == "":
		return errors.New("-gate-audit needs -data")
	case baselineID != "" && dataDir == "":
		return errors.New("-baseline needs -data")
	case notify && dataDir == "":
		return errors.New("-notify needs -data")
	case failOnNew && baselineID == "":
		return errors.New("-fail-on-new needs -baseline")
	}
	return nil
}

// loadRun reads one saved run from a data directory.
func loadRun(dataDir, id string) (record.Run, error) {
	st, err := store.Open(dataDir)
	if err != nil {
		return record.Run{}, err
	}
	run, err := st.Get(id)
	if err != nil {
		return record.Run{}, fmt.Errorf("run %q: %w", id, err)
	}
	return run, nil
}

// loadBaseline returns nil when no baseline was asked for.
func loadBaseline(dataDir, id string) (*record.Run, error) {
	if id == "" {
		return nil, nil
	}
	run, err := loadRun(dataDir, id)
	if err != nil {
		return nil, fmt.Errorf("baseline %w", err)
	}
	return &run, nil
}

// printChanges writes what changed since the baseline and reports whether
// anything is new. It goes to standard error because standard output may be
// carrying the report.
func printChanges(baseline, head record.Run, stderr io.Writer) bool {
	diff := rundiff.Compare(baseline, head)
	fmt.Fprint(stderr, diff.Markdown())
	return diff.HasNew()
}

// notifyRun posts the summary of a saved run. A failure is only a warning:
// the run is complete and saved, and a webhook being down must not change
// what a pipeline concludes from the findings.
func notifyRun(ctx context.Context, cfg config.Config, deps app.Deps, run record.Run, stderr io.Writer) {
	if err := app.Notify(ctx, cfg, deps, run); err != nil {
		fmt.Fprintf(stderr, "vajra: warning: the run was saved but the notification was not sent: %v\n", err)
		return
	}
	fmt.Fprintf(stderr, "vajra: sent a summary of run %s to the webhook\n", run.ID)
}

// withOperatorControls gives the autonomous explorer its two links to the
// person running the scan: a prompt before requests that could change data,
// when the configuration asks for one, and a stop file in the data directory.
func withOperatorControls(deps app.Deps, cfg config.Config, dataDir string, stdin io.Reader, stderr io.Writer) (app.Deps, error) {
	if cfg.Agent != nil && cfg.Agent.UnsafeRequests == config.UnsafeAsk {
		deps.Approve = terminalApprover(stdin, stderr)
	}
	if dataDir == "" {
		return deps, nil
	}
	// The directory must exist while the scan runs, not only once the run is
	// saved, or "vajra stop" would have nowhere to put the file.
	if _, err := store.Open(dataDir); err != nil {
		return deps, err
	}
	// A file left by an earlier "vajra stop" would end this scan's explorer
	// before its first step.
	if err := os.Remove(stopPath(dataDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return deps, err
	}
	deps.Stop = stopRequested(dataDir)
	return deps, nil
}

func stopPath(dataDir string) string {
	return filepath.Join(dataDir, stopFileName)
}

// stopRequested returns a function that reports whether the stop file exists.
// It is polled between the explorer's steps.
func stopRequested(dataDir string) func() bool {
	path := stopPath(dataDir)
	return func() bool {
		_, err := os.Stat(path)
		return err == nil
	}
}

// terminalApprover asks the operator on the terminal before the explorer
// sends a request that could change data. Only "y" or "yes" on a complete
// line allows it: no answer, a closed input and an unfinished line all mean
// no, so a scan with nobody at the keyboard refuses instead of proceeding.
func terminalApprover(in io.Reader, out io.Writer) agent.Approver {
	var mu sync.Mutex
	lines := bufio.NewReader(in)
	// pending is a read that an earlier, cancelled question left behind. A
	// read from a terminal cannot be interrupted, so the next question reuses
	// it instead of starting a second reader on the same input.
	var pending chan string
	return func(ctx context.Context, action string) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(out, "Allow the explorer to send: %s? [y/N] ", printable(action))
		if pending == nil {
			pending = make(chan string, 1)
			go readAnswer(lines, pending)
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case answer := <-pending:
			pending = nil
			return answer == "y" || answer == "yes", nil
		}
	}
}

// readAnswer sends one normalised line, or "" when the input ended or failed
// before the line did.
func readAnswer(lines *bufio.Reader, answers chan<- string) {
	line, err := lines.ReadString('\n')
	if err != nil {
		line = ""
	}
	answers <- strings.ToLower(strings.TrimSpace(line))
}

// printable makes text that came from a model or a remote service safe to
// show on one terminal line. Control and formatting characters could
// otherwise redraw the line, for example to disguise the request an operator
// is being asked to approve.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
}
