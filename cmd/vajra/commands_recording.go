package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/dhruv29/vajra/internal/config"
	"github.com/dhruv29/vajra/internal/har"
)

// suggestedCheck has the shape of one entry of auth.access_checks in the run
// configuration, so the output can be pasted there.
type suggestedCheck struct {
	Name   string   `json:"name"`
	Method string   `json:"method"`
	URL    string   `json:"url"`
	Allow  []string `json:"allow"`
}

// runRecording reads a browser recording against a configuration's scope and
// prints what a scan would take from it, followed by access checks drafted
// from the pages that were requested while signed in.
//
// The drafts are suggestions, never findings: a browser sends its cookies to
// public pages too, so only the operator can say which of these pages are
// really private. Reporting them unasked would be guesswork.
func runRecording(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("recording", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to the run configuration, for its scope (required)")
	harPath := flags.String("har", "", "the browser recording, a HAR file (required)")
	allow := flags.String("allow", "", "name of the identity the recording was made as; it goes into each drafted check's allow list")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *harPath == "" {
		return errors.New("-config and -har are required")
	}
	_, policy, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if policy == nil {
		return errors.New("this configuration has no scope, so no recorded address can be accepted")
	}
	file, err := os.Open(*harPath)
	if err != nil {
		return err
	}
	defer file.Close()
	recording, err := har.Parse(file, policy, har.Options{})
	if err != nil {
		return err
	}
	skipped := recording.Skipped
	fmt.Fprintf(stderr, "vajra: %d page(s) a scan would add; %d request(s) outside the scope and %d unusable were dropped\n",
		len(recording.URLs), skipped.OutOfScope, skipped.Malformed+skipped.UnsupportedScheme+skipped.OverLimit)
	checks := draftChecks(recording, *allow)
	fmt.Fprintf(stderr, "vajra: %d access check(s) drafted from pages requested while signed in; delete the public ones before using them\n", len(checks))
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(checks)
}

// draftChecks drafts one check per read-only request that carried
// credentials. Requests that change state are left out: a check is repeated
// as every identity, and repeating those would change data several times.
func draftChecks(recording har.Recording, allow string) []suggestedCheck {
	checks := []suggestedCheck{}
	seen := map[string]bool{}
	for _, request := range recording.Requests {
		if !request.Authenticated || request.StateChanging || request.Method != "GET" || seen[request.URL] {
			continue
		}
		seen[request.URL] = true
		check := suggestedCheck{Name: fmt.Sprintf("recorded-%d", len(checks)+1), Method: request.Method, URL: request.URL, Allow: []string{}}
		if allow != "" {
			check.Allow = []string{allow}
		}
		checks = append(checks, check)
	}
	return checks
}
