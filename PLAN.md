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
| 1 | Scope policy, egress proxy, sandbox runner, budgets, finding model, verification pipeline, nuclei adapter, LLM refuter, CLI | in progress |
| 2 | Store, asset graph, blast-radius engine, report generator, HTTP API | planned |
| 3 | Web UI: runs, findings triage, blast-radius graph, run reach, report export | planned |

### Phase 2: full coverage of an application

| Loop | Delivers |
|---|---|
| 4 | SAST: Semgrep adapter, secrets and dependency scanning, source-to-sink verification |
| 5 | SAST and DAST correlation: code findings steer live tests; live results confirm code findings |
| 6 | Authenticated testing: login flows, session handling, role-based access checks across accounts |
| 7 | Traffic capture: recording proxy, browser-driven crawling, evidence bound to exact exchanges |
| 8 | API testing: OpenAPI and GraphQL import, authorisation and business-logic checks |

### Phase 3: autonomy under gates

| Loop | Delivers |
|---|---|
| 9 | Planner and workers: goal decomposition, an exploration graph, every action through the same gates |
| 10 | Recon: sub-domain and service discovery limited to the declared scope; a SOCKS gate for raw TCP tools |
| 11 | Attack chains: combine confirmed findings into multi-step paths, each step re-proven |
| 12 | Human-in-the-loop controls: approvals for risky actions, pause, resume, and a full action timeline |

### Phase 4: beyond the state of the art

| Loop | Delivers |
|---|---|
| 13 | Benchmark harness: scheduled runs against deliberately vulnerable apps; published precision and recall |
| 14 | Fix verification: propose a patch, apply it in a sandbox copy, prove the exploit no longer works |
| 15 | Continuous mode: run on every commit and deploy; report only what changed since the last run |
| 16 | Exposure intelligence: match newly published vulnerabilities to the assets and versions already mapped, then test only those |
| 17 | Cross-model review: a second, different model re-judges high-severity findings; disagreements go to a person |
| 18 | Team features: roles, audit trail, ticketing and chat integrations, signed reports |
| 19 | Hardened distribution: reproducible builds, signed images, software bill of materials |

## Decisions taken

- Fresh codebase with no code taken from other projects.
- Go, standard library first, single binary with the UI embedded.
- UI is plain HTML, CSS and JavaScript modules served from the binary: no
  build step and no third-party scripts, so a strict content-security policy
  is possible.
- JSON configuration (no YAML dependency).

## Open questions

- Licence for this repository.
- Raw TCP tools (port scanning) need a SOCKS or transparent gate; the first
  proxy speaks HTTP and CONNECT only.
- Which model backs the refuter by default, and whether a second, different
  model should cross-check high-severity findings.
- Multi-user access and roles for team use.

## Authorised use

Vajra refuses to start a run without a scope and an authorisation statement
naming who approved the test. Test only systems you own or have written
permission to test.
