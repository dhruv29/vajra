package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/dhruv29/vajra/internal/app"
	"github.com/dhruv29/vajra/internal/finding"
	"github.com/dhruv29/vajra/internal/record"
	"github.com/dhruv29/vajra/internal/report"
	"github.com/dhruv29/vajra/internal/ticket"
)

// Credentials for filing come only from the environment, never from flags:
// a flag value would sit in shell history and in the process list.
const (
	envGitHubToken = "VAJRA_GITHUB_TOKEN"
	envJiraEmail   = "VAJRA_JIRA_EMAIL"
	envJiraToken   = "VAJRA_JIRA_TOKEN"

	trackerGitHub = "github"
	trackerJira   = "jira"
)

type ticketFlags struct {
	dataDir, runID, findingID, outPath string
	tracker, repo                      string
	jiraURL, jiraProject, jiraType     string
	force                              bool
}

// runTicket prints one finding as a Markdown issue, for pasting into a
// tracker: the title on the first line, then a blank line, then the body.
// With -file it files the issue in GitHub or Jira instead, or reports the
// ticket already filed for the same finding.
func runTicket(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	tf, err := parseTicketFlags(args, stderr)
	if err != nil {
		return err
	}
	run, err := loadRun(tf.dataDir, tf.runID)
	if err != nil {
		return err
	}
	title, body, err := report.Ticket(run, tf.findingID)
	if err != nil {
		return err
	}
	if tf.tracker == "" {
		return printTicket(title, body, tf.outPath, stdout)
	}
	if err := checkFileable(run, tf.findingID, tf.force); err != nil {
		return err
	}
	filer, err := newFiler(tf, newDeps())
	if err != nil {
		return err
	}
	result, err := filer.File(ctx, ticket.Issue{FindingID: tf.findingID, Title: title, Body: body})
	if err != nil {
		return err
	}
	printFiled(stdout, result)
	return nil
}

func parseTicketFlags(args []string, stderr io.Writer) (ticketFlags, error) {
	var tf ticketFlags
	flags := flag.NewFlagSet("ticket", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&tf.dataDir, "data", "", "data directory (required)")
	flags.StringVar(&tf.runID, "run", "", "run ID (required)")
	flags.StringVar(&tf.findingID, "finding", "", "finding ID, as shown in the report (required)")
	flags.StringVar(&tf.outPath, "out", "", "write here instead of standard output (not with -file)")
	flags.StringVar(&tf.tracker, "file", "", "file the issue in github or jira instead of printing it; an existing ticket for the finding is reported, not duplicated")
	flags.StringVar(&tf.repo, "repo", "", "GitHub repository as owner/name (with -file github; token in "+envGitHubToken+")")
	flags.StringVar(&tf.jiraURL, "jira-url", "", "Jira site, such as https://example.atlassian.net (with -file jira; credentials in "+envJiraEmail+" and "+envJiraToken+")")
	flags.StringVar(&tf.jiraProject, "jira-project", "", "Jira project key, such as SEC (with -file jira)")
	flags.StringVar(&tf.jiraType, "jira-type", ticket.DefaultJiraIssueType, "Jira issue type (with -file jira)")
	flags.BoolVar(&tf.force, "force", false, "file a finding that is not confirmed")
	if err := flags.Parse(args); err != nil {
		return tf, err
	}
	if tf.dataDir == "" || tf.runID == "" || tf.findingID == "" {
		return tf, errors.New("-data, -run and -finding are required")
	}
	return tf, checkTrackerFlags(tf)
}

// checkTrackerFlags catches a missing or misplaced tracker flag before the
// run is loaded, so the mistake is named instead of surfacing later.
func checkTrackerFlags(tf ticketFlags) error {
	switch tf.tracker {
	case "":
		if tf.repo != "" || tf.jiraURL != "" || tf.jiraProject != "" || tf.force {
			return errors.New("-repo, -jira-url, -jira-project and -force need -file")
		}
		return nil
	case trackerGitHub:
		if tf.repo == "" {
			return errors.New("-file github needs -repo owner/name")
		}
	case trackerJira:
		if tf.jiraURL == "" || tf.jiraProject == "" {
			return errors.New("-file jira needs -jira-url and -jira-project")
		}
	default:
		return fmt.Errorf("unknown tracker %q for -file: use github or jira", tf.tracker)
	}
	if tf.outPath != "" {
		return errors.New("-out cannot be used with -file")
	}
	return nil
}

func printTicket(title, body, outPath string, stdout io.Writer) error {
	text := []byte(title + "\n\n" + body)
	if outPath == "" {
		_, err := stdout.Write(text)
		return err
	}
	return writePrivate(outPath, text)
}

// checkFileable refuses to file a finding that verification did not
// confirm. A ticket asks someone to act, and a refuted or undecided finding
// filed by habit is exactly the noise this tool exists to remove.
func checkFileable(run record.Run, findingID string, force bool) error {
	for _, f := range run.Report.Findings {
		if f.ID != findingID {
			continue
		}
		if f.Status != finding.Confirmed && !force {
			return fmt.Errorf("finding %s is %s, not %s; only confirmed findings are filed (use -force to file it anyway)", findingID, f.Status, finding.Confirmed)
		}
		return nil
	}
	return fmt.Errorf("run %s has no finding %q", run.ID, findingID)
}

// newFiler reads the credentials from the environment and builds the filer.
// The error names the variable, never its value.
func newFiler(tf ticketFlags, deps app.Deps) (ticket.Filer, error) {
	getenv := deps.Getenv
	if tf.tracker == trackerGitHub {
		token := strings.TrimSpace(getenv(envGitHubToken))
		if token == "" {
			return nil, fmt.Errorf("set %s to a GitHub token that can create issues in %s", envGitHubToken, tf.repo)
		}
		return ticket.NewGitHub(ticket.GitHubOptions{BaseURL: deps.GitHubBaseURL, Repo: tf.repo, Token: token})
	}
	email, token := strings.TrimSpace(getenv(envJiraEmail)), strings.TrimSpace(getenv(envJiraToken))
	if email == "" || token == "" {
		return nil, fmt.Errorf("set %s and %s to the Atlassian account and its API token", envJiraEmail, envJiraToken)
	}
	return ticket.NewJira(ticket.JiraOptions{
		BaseURL: tf.jiraURL, Project: tf.jiraProject, IssueType: tf.jiraType, Email: email, Token: token,
	})
}

// printFiled reports the ticket. The tracker's reply is printed through
// printable, so a hostile reply cannot send terminal control sequences.
func printFiled(stdout io.Writer, result ticket.Result) {
	if !result.Existing {
		fmt.Fprintf(stdout, "filed %s: %s\n", printable(result.Key), printable(result.URL))
		return
	}
	state := ""
	if result.State != "" {
		state = " (" + printable(result.State) + ")"
	}
	fmt.Fprintf(stdout, "already filed as %s%s, not filed again: %s\n", printable(result.Key), state, printable(result.URL))
}
