# Vajra: project plan

An autonomous security-testing toolkit for defenders: it tests
applications you are authorised to test, proves or refutes every finding before
reporting it, and shows what each confirmed finding actually puts at risk.

## Who it is for

Security teams drowning in scanner output and vulnerability news. The product
goal is fewer, truer findings: a short list of issues that were reproduced,
with evidence, ranked by what an attacker could reach from each one.

## Principles

1. **Gates live outside the model.** Scope, isolation and budgets are enforced
   by code and by the container network. A prompt is never a control.
2. **Deny by default.** No scope means no run. No budget means no run.
3. **Scanners find, the pipeline judges.** Detection comes from deterministic
   tools; the model only triages, verifies and explains.
4. **Nothing is reported unproven.** A finding is `confirmed` only after it was
   reproduced and survived a refutation pass. Anything else is labelled, never
   silently dropped.
5. **Evidence or it did not happen.** Every finding carries the request and
   response, or the source-to-sink path, that proves it.
6. **Small trusted base.** Standard library first; every dependency is a
   decision. No runtime downloads inside a task.

## What sets Vajra apart

| Area | Common in autonomous testing tools | Vajra |
|---|---|---|
| Scope | Advisory; shell commands unchecked | Network-level allow-list; no route out except the gated proxy |
| Approvals | A bypass mode that agents run in by default | No bypass mode exists; capabilities are granted per task |
| Isolation | One shared shell, often as the operator's own user | One throwaway container per tool run; refuses to run unsandboxed |
| Findings | Model-written, evidence optional in practice | Reproduced and refuted before `confirmed` |
| Code analysis | A prompt that reads source | SAST engine, correlated with live testing |
| Impact | A severity label | Blast radius: what the finding reaches |
| Accuracy | Unmeasured | Benchmarked precision and recall per release |
| Spend | Unlimited unless configured | Mandatory token, turn, run and time limits |

## Architecture

```
            operator
               |
        UI / CLI / API            (loop 3)
               |
          orchestrator ---------- budget (tokens, turns, runs, time)
           |        |
     scanners     verifier ------ refuter (LLM, sees evidence as data)
           |        |
        sandbox runner            one container per tool run:
               |                  read-only root, no capabilities,
       internal network           no host env, non-root, resource caps
               |
         egress proxy ----------- scope policy + audit log
               |
            targets
```

A task container sits on a Docker network with no route out. The only peer it
can reach is the egress proxy, which checks every connection against the scope
policy, pins the resolved address, and writes an audit record.

## Finding lifecycle

`candidate` -> evidence check -> scope check -> reproduction -> refutation ->
`confirmed` | `refuted` | `unconfirmed` | `out_of_scope`

- A failed reproduction or a successful refutation gives `refuted`.
- An inconclusive stage (tool error, model unsure, budget spent) gives
  `unconfirmed`, which is shown to the operator, not hidden.

## Blast radius

Two views, both shown in the UI:

1. **Impact radius of a finding.** Starting from the affected asset, follow
   edges in the asset graph that the vulnerability class makes traversable:
   same host, shared credentials or sessions, downstream services the asset
   calls, data stores it reads. Each hop is labelled with why it is reachable
   and how sure we are (proven, inferred, assumed). Output: reachable assets,
   data classes exposed, and a 0-100 score used for ranking.
2. **Reach of a run.** What the test itself was allowed to touch and did
   touch: the scope policy, every allowed and denied connection from the audit
   log. This is the answer to "what did this tool do on my network".

## Reports

Generated from stored findings, never from model memory:

- Executive summary: counts by status and severity, top risks by blast radius.
- Per finding: evidence, reproduction steps, verification verdicts, blast
  radius, remediation.
- Appendix: scope, budgets used, audit summary, refuted and unconfirmed items.
- Formats: JSON (machine), Markdown, self-contained HTML (printable to PDF).

## Phases

Work proceeds in loops. Each loop is plan -> tests -> build -> review -> fix,
ends with something that runs, and is committed when its tests pass.

### Phase 1: a trustworthy core

The gates and the verification pipeline. Nothing else is safe to build first.

| Loop | Delivers | State |
|---|---|---|
| 1 | Scope policy, egress proxy, sandbox runner, budgets, finding model, verification pipeline, nuclei adapter, LLM refuter, CLI | done |
| 2 | Run store, asset graph, blast-radius engine, Markdown and HTML reports, run reach from the gate audit log | done |
| 3 | Read-only HTTP API and web UI: runs, findings by blast radius, reach graph, run reach, report export, sample run | done |

### Phase 2: full coverage of an application

| Loop | Delivers | State |
|---|---|---|
| 4a | SAST: Semgrep in a no-network sandbox, source read and confined by Vajra itself, code-review refuter, starter rules, code findings anchored to their service | done |
| 4b | Built-in secret search with masked values; dependency advisories from OSV (opt-in) | done |
| 5 | Code and live findings corroborate each other; code findings are given to the explorer as leads to demonstrate live | done |
| 6 | Test accounts, scanning as an account, access rules checked across every account | done |
| 7 | Link-following crawler behind the gate | done; a recording proxy and browser-driven crawling are not built |
| 8 | OpenAPI import; protected operations requested without credentials | done; GraphQL and business-logic checks are not built |

### Phase 3: autonomy under gates

| Loop | Delivers | State |
|---|---|---|
| 9 | Explorer limited to three gated tools, with evidence-bound reports and a step timeline | done |
| 10 | Sub-domain discovery under wildcard scope; SOCKS5 front end on the gate | done; no port scanner uses the SOCKS5 gate yet |
| 11 | Attack chains across confirmed findings | done |
| 12 | Terminal approval for requests that could change data; stop command; timeline in the run | done; pause and resume are not built |

### Phase 4: beyond the state of the art

| Loop | Delivers | State |
|---|---|---|
| 13 | Scoring against an answer key; a key for the lab | done; scheduled runs against public vulnerable apps and published numbers are not |
| 14 | Patch proposal, applied to a copy and re-checked with the rule | done for code findings |
| 15 | Baseline comparison, fail only on new findings, example pipeline | done |
| 16 | New advisories matched to a run's recorded dependencies | done for dependencies; service versions are not matched |
| 17 | A second model must also hold serious findings | done within one provider |
| 18 | Signed reports, webhook summaries | done; user accounts, roles and ticketing are not built |
| 19 | Reproducible build, zero third-party modules, base images pinned by digest, SBOM, CI | done; images are not signed |

## Not yet proven

Everything marked done is unit-tested. `scripts/e2e.sh` additionally runs the
gate, live scanning, code analysis, access checks, API tests and the secret
search against lab targets. These have run only against a stand-in for the
model API, never the real one: the reviewer, the second reviewer, the
explorer and the patch proposer. Discovery, crawling, dependency lookups and
the SOCKS5 gate have unit tests only. Blast-radius rules and scores are
uncalibrated heuristics.

## Hardening from review

An independent review of the core (2026-11-21) found no way to reach
`confirmed` without passing every stage. Its findings, all now fixed and
tested:

- The task network is inspected before every live scan and must be internal.
- A re-test that gets no answer is inconclusive, not a refutation. A canary
  template tells the two apart, and the gate marks its own error responses.
- Zoned, IPv4-compatible, NAT64, 6to4 and Teredo addresses are never targets.
- The check, the DNS lookup and the connection all use one normalised host.
- The time budget cuts off running tools and model calls.
- The gate times out idle tunnels, logs before forwarding, and forwards
  nothing if the audit log cannot be written.
- Sandbox mounts are read-only unless stated; user IDs are parsed, not matched.
- One oversized scanner record no longer discards a whole scan.

Since then: leftover containers can be removed with `vajra cleanup`, and base
images are pinned by digest. Still open from that review: wildcards over
public suffixes such as `*.co.uk` are accepted.

## Open questions

- Which raw TCP tools to run behind the SOCKS5 gate, and how to verify what
  they report.
- Whether the second reviewer should come from a different provider.
- Multi-user access and roles for team use.

## Authorised use

Vajra refuses to start a run without a scope and an authorisation statement
naming who approved the test. Test only systems you own or have written
permission to test.
