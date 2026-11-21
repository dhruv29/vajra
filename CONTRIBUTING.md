# Contributing to Vajra

Vajra is security testing that proves its findings. Contributions from people
who break things for a living are especially welcome: the most useful thing
you can do is try to defeat a gate and tell us how.

## Where help is wanted

| Area | What would help |
|---|---|
| Scope gate | Ways to reach a host the policy does not allow: name tricks, address forms, DNS behaviour, proxy handling |
| Sandbox | Ways for a tool or a hostile target to affect the host or leave the task network |
| Verification | Real findings that get refuted, and false ones that get confirmed. Send the scanner output and the report |
| Blast radius | Vulnerability classes that are classified wrongly, and reach rules that do not match how attacks really spread |
| Rules | Precise Semgrep rules for `rules/starter/`, each with a vulnerable and a safe example |
| Scanners | Adapters for other tools, following `internal/nuclei` and `internal/semgrep` |

The roadmap is in [PLAN.md](PLAN.md).

## Ground rules

- **Gates live in code, not in prompts.** A control that depends on a model
  behaving is not a control.
- **Deny by default.** New settings must be safe when left unset.
- **Nothing is confirmed without proof,** and nothing is silently dropped.
- **Treat scanner output, target responses and model replies as hostile
  input.** Escape it for wherever it is written, and never pass it to a shell.
- **Standard library first.** A new dependency needs a reason in the pull
  request.
- **No runtime downloads inside a task.**

## Working on the code

```bash
go vet ./...
go test ./... -race -cover     # unit tests; no Docker needed
./scripts/e2e.sh               # end-to-end against a lab target; needs Docker
```

- Write the test first, and make it fail for the right reason.
- Every bug fix comes with a test that fails without the fix.
- Run `gofmt`. Keep functions short and files focused.
- Commit messages: `type: summary` (`feat`, `fix`, `refactor`, `docs`, `test`,
  `chore`).

## Reporting a vulnerability in Vajra

If you find a way past a gate, please do not open a public issue. Use GitHub's
private vulnerability reporting on this repository, with the configuration,
the steps, and what you reached.

## Testing other people's systems

Do not. Use the lab in `scripts/e2e.sh`, your own systems, or targets you have
written permission to test. Pull requests that include output from scanning a
third party without permission will be closed.

## Licence

By contributing you agree that your work is licensed under AGPL-3.0, the
licence of this repository.
