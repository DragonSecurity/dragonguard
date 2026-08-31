# DragonGuard

An open-source application security platform: the scanners are commodities, the
control plane is the product.

DragonGuard runs OSS security engines, normalizes what they find into one
schema, scores it against your actual deployment context, evaluates your
policies, and decides whether a change is fit to ship.

```
Policies determine what is risky.
Scorecards tell you where you stand.
Baselines determine whether you can ship.
```

## The idea

Building a Snyk-shaped product is not "write a vulnerability scanner". Trivy,
OpenGrep, Gitleaks, OSV and ZAP already find the problems, and they are
interchangeable. What is missing between a pile of security CLIs and a product
is the layer that decides what the findings *mean* for one particular
deployment — and then acts on it consistently, on every pull request, forever.

That layer is four things:

| Component | What it does |
|---|---|
| **Dragon Risk** | Enrichment plus scoring. CVSS, EPSS, KEV, reachability, asset context and remediation collapse into one 0-100 number. |
| **Dragon Policy** | CEL evaluation of individual evidence. Returns decisions, never side effects. |
| **Dragon Scorecard** | Aggregated posture, per dimension and overall. |
| **Dragon Baseline** | The circuit breaker. Hard gates, score gates and regression gates produce PASS / WARN / BLOCK. |

```
   OpenGrep ─┐
      Trivy ─┤
   Gitleaks ─┤   evidence
        OSV ─┤
  Scorecard ─┘
              │
              ▼
       normalize + dedupe          one Finding schema
              │
              ▼
     EPSS · KEV · reachability     enrichment
              │
              ▼
        Dragon Risk                0-100, higher is worse
              │
              ▼
        Dragon Policy (CEL)        allow · warn · deny
              │
              ▼
       Dragon Scorecard            0-100 per dimension, higher is better
              │
              ▼
       Dragon Baseline             the circuit breaker
              │
        ┌─────┼─────┐
      PASS   WARN  BLOCK
```

## Quick start

```sh
go build -o bin/dragon ./cmd/dragon

dragon init          # .dragon.yaml, a baseline, a policy pack
dragon engines       # what can actually run here
dragon scan          # scan, score, gate
dragon scan --record # record the baseline the ratchet compares against
```

Exit status is the verdict: `0` for pass or warn, `1` for block, `2` when the
scan itself could not complete. A scan that could not run is deliberately not
the same as a scan that found nothing.

## What a scan looks like

```
Dragon Scorecard
----------------------------------------------
  Overall                   60/100
  Code                      42   10M
  Dependencies              59    9M
  Container                100
  IaC                       92   1M 1L
  Secrets                   70    1C
  API                      not assessed
  Supply Chain             not assessed

Dragon Risk
----------------------------------------------
   91  GitHub Personal Access Token NEW
       SECRET  creds.env:2
       why: severity critical; committed credential is directly usable

   89  Shell command built from a variable NEW
       SAST  vuln.js:5
       why: CVSS 9.0; production, internet-exposed; directly exploitable

   69  nodejs-lodash: command injection via template NEW
       SCA  package-lock.json  CVE-2021-23337  EPSS 0.21
       why: CVSS 7.2, EPSS 0.213; fix available
       fix: lodash 4.17.11 -> 4.17.21

Dragon Baseline
----------------------------------------------
  !!  complete evidence              all engines available   degraded
  XX  no_active_secrets              true                    false
  OK  no_kev_in_production           true                    true
  OK  new critical findings          <= 0                    0
  XX  policy denials                 0                       2

Dragon Gate: BLOCKED   posture 60 (was 74)

  - mandatory condition "no_active_secrets" is not satisfied
  - 2 finding(s) denied by policy
  - scan was degraded: dimensions not assessed (api, supply_chain)
```

## Dragon Risk

Risk is deterministic application logic, not policy. Policy decides what to do
about a risk; it should not also be where the arithmetic lives. Keeping the
maths out of the policy language is what makes a score reproducible, testable,
and comparable over time.

| Component | Weight | Inputs |
|---|---:|---|
| Vulnerability | 35% | CVSS, EPSS, CISA KEV |
| Exploitability | 20% | reachability, exploit maturity |
| Asset context | 15% | environment, criticality, exposure, data handled |
| Supply chain | 15% | OpenSSF Scorecard |
| Remediation | 10% | fix available, upgrade path |
| Provenance | 5% | VEX |

**Components with no evidence are excluded and their weight redistributed.** A
neutral placeholder is indistinguishable from real evidence once it has been
multiplied by a weight, and it drags genuine emergencies toward the middle of
the range. If a package's upstream posture is unknown, the score reflects what
*is* known — more confidently, not less. Each score carries a `confidence`
value saying how much of the weight was actually backed by evidence.

This is the whole argument for the platform, in two findings:

```
CVSS 9.8, EPSS 0.001, unreachable, dev dependency     ->  26  LOW
CVSS 7.5, EPSS 0.91, KEV, reachable, internet-facing  ->  93  CRITICAL
```

Sorting that queue by CVSS gets the order exactly backwards. Both cases are
locked in as tests in `internal/risk/risk_test.go`.

### Two scales, deliberately

Dragon Risk runs 0-100 where **higher is worse** — it ranks a queue of findings
for an engineer. A scorecard runs 0-100 where **higher is better** — it
describes health for whoever decides to ship. Different metrics, different
audiences.

## Dragon Policy

CEL rather than Rego. The language is non-Turing-complete, so a customer policy
cannot hang the gate; it type-checks ahead of evaluation; and its surface is
small enough to generate safely from a form-based UI. Rego's strength is
composition over large sets of resources and relationships, which is not the
shape of this problem — every rule here is a predicate over one finding.

```yaml
rules:
  - id: kev-in-production
    description: Actively exploited vulnerability in a production asset.
    when: threat.kev && asset.environment == "production"
    then:
      decision: deny
      actions: [block_merge, create_ticket, notify_security]
      risk_boost: 10
      tags: [kev, must-fix]
```

Rules can also be written structurally, so a UI can author them without ever
exposing an expression language. Both forms compile to the same CEL, and
`dragon policy list` prints what a structured rule became — a form-authored
policy stays as auditable as a hand-written one.

```yaml
    match:
      all:
        - risk.score >= 90
        - analysis.reachable
        - asset.internet_exposed
      none:
        - component.dev_only
```

Available context: `finding`, `threat`, `analysis`, `risk`, `asset`,
`component`, `scan`. (`component`, not `package` — `package` is a CEL reserved
word.)

**Policies return decisions, never side effects.** A rule can ask for
`create_ticket`; only the enforcement layer knows what that means. That
boundary is what stops a policy language from slowly becoming an integration
runtime.

**Evaluation is aggregate**, not first-match: every matching rule contributes.
The scorecard downstream needs all of them, and a security review that stops at
the first hit hides the rest of what is wrong.

### Mistakes are caught when written, not during a release

`dragon policy test` compiles every rule *and* proves it evaluates against a
canonical finding. CEL types a map lookup as `dyn`, so `threat.kevv` compiles
cleanly and then silently never matches — a policy you believe is enforcing
something that is not. The load-time evaluation turns that into an error you
see immediately.

## Dragon Baseline

Following OpenSSF Scorecard's own advice about aggregate scores: do not gate on
the number alone. A single threshold is both too blunt to catch what matters
and too easy to satisfy by fixing whatever is cheapest.

```yaml
mandatory:                      # hard gates, unacceptable at any score
  - no_active_secrets
  - no_kev_in_production
  - no_reachable_critical_vulnerability

critical: {maximum_new: 0}
high:     {maximum_new: 2}

maximum_score_regression: 5     # the ratchet

dimensions:                     # score gates
  secrets:
    minimum: 100
    required: true              # must actually be assessed
  dependencies:
    minimum: 75
    maximum_regression: 3

block_on_policy_deny: true
allow_degraded: false
warn_only: false                # while introducing the gate to a team
```

**The regression gate is what makes this adoptable.** A legacy codebase cannot
pass an absolute floor on day one, but it can pass "no worse than yesterday"
immediately — and that ratchet is what actually moves posture. A gate nobody
can ever pass gets switched off within a week.

**`allow_degraded: false` is the default and it matters.** A dimension no
engine covered is reported as *not assessed*, never as clean, and a scan that
was missing engines cannot report a clean pass. A gate that passes because it
could not look is not a gate.

## Evidence

| Engine | Covers | Status |
|---|---|---|
| Trivy | SCA, container, IaC, secrets, licences, dependency graph | implemented |
| OpenGrep | SAST | implemented |
| Gitleaks | secrets, including git history | implemented |
| OSV-Scanner | SCA, **call-analysis reachability** | implemented |
| deps.dev | OpenSSF Scorecard, dependency graph, versions | implemented |
| OWASP ZAP | DAST | implemented |
| Schemathesis | API property testing | implemented |

Adding an engine means implementing one interface:

```go
type Scanner interface {
    Name() string
    Categories() []finding.Category
    Available(ctx context.Context, t Target) (bool, string)
    Scan(ctx context.Context, t Target) ([]finding.Finding, error)
}
```

`Available` takes the target because availability is not only about a binary
being installed: a DAST engine with no configured URL is unavailable in exactly
the same sense, and reporting that as a scan *failure* would mark every
unconfigured project as degraded.

An engine that also parses lockfiles can report the dependency graph in the
same pass by implementing `GraphScanner`, which is what lets remediation name
the direct dependency without a second read.

Nothing downstream of normalization knows which tool produced the evidence,
which is what lets an engine be swapped without touching the control plane.

### Deduplication is cross-engine

The same CVE in the same package is one problem whether Trivy or Grype found
it, and a credential at a location is one credential. Fingerprints exclude the
scanner name for evidence whose identity does not depend on who found it, and
exclude line numbers so a finding that moved down the file keeps its identity.
SAST is the exception: rule semantics are engine-specific, so two engines
flagging one line are making two different claims.

When engines do overlap, the findings are **merged**, not dropped — each
usually knows something the other does not. Trivy resolves a fixed version;
Gitleaks knows which commit introduced the credential. The merge is monotone:
it only ever adds information or raises severity, so the result never depends
on the order engines are listed in.

## Dragon Rules

`rules/` holds DragonGuard's own SAST rules in Semgrep-format YAML.

OpenGrep runs Semgrep-format rules unchanged, but engine compatibility is not
permission to redistribute anybody's ruleset: the engine is LGPL 2.1, while
Semgrep-maintained rules carry terms restricting use in a competing hosted
service. So these are original, deliberately few, and deliberately
high-precision. A rule that fires on safe code costs more than it saves.

Point the engine anywhere:

```yaml
engines:
  opengrep:
    rules: [./rules, p/security-audit, ./my-org-rules]
```

## CI

```yaml
- run: dragon scan --format sarif --output dragon.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: {sarif_file: dragon.sarif}
```

Dragon Risk is carried in SARIF's `security-severity` rather than the `level`
field, because `level` has three values and the argument of this whole platform
is that three buckets is not enough information to act on.

`--format markdown` produces a PR comment: verdict and reasons first, findings
collapsed behind a disclosure. A review comment nobody reads enforces nothing.

## Commands

```
dragon scan [path]              scan, score, gate
dragon scan code|dependencies|container|iac|secrets
dragon scan --format json|sarif|markdown
dragon scan --record            record the baseline snapshot
dragon scan --offline           no network, including threat intelligence

dragon policy test              compile and validate policy packs
dragon policy list              show rules and the CEL they compile to
dragon policy eval --finding f.yaml

dragon baseline init            write a starter baseline
dragon baseline show            print the effective baseline
dragon baseline status          show the recorded snapshot

dragon findings list --kev --fixable --new
dragon findings show <cve|fingerprint>

dragon engines                  what can run here
dragon init                     scaffold a project

dragon baseline calibrate       scan, then write a baseline this project can pass
dragon push                     scan and submit to a DragonGuard server
```

`baseline calibrate` is the adoption path. It scans, reads where the project
actually stands, and writes floors just below that — because a guessed
`minimum_score: 80` on an unfamiliar codebase blocks every pull request for
reasons nobody caused, and the gate is disabled by Friday.

It does not calibrate around committed credentials, and says so rather than
quietly promising a pass it cannot deliver.

## Reachability

OSV-Scanner's call analysis answers the question that decides whether a queue
has 200 items or 12: is the vulnerable function actually reachable from your
code?

```yaml
engines:
  osv:
    rules: [go]     # call-analysis languages; go and rust are supported
```

The distinction the pipeline is careful to preserve: call analysis finding no
path is **unreachable**, a real conclusion that heavily discounts the score.
Call analysis not having run is **unknown**, which does not. Collapsing the two
would either discard the signal or invent it.

## Remediation

A scanner says "lodash is vulnerable, fixed in 4.17.21". But nothing depends on
lodash directly — some build tool three levels up does, and telling somebody to
upgrade a package that is not in their manifest is how findings get closed as
"won't fix".

```
qs@6.7.0 is pulled in via express@4.17.1 -> qs; needs qs >= 6.14.2 -- upgrade express
```

The graph comes from Trivy's own `DependsOn` output where available — local,
offline, and reflecting what this project actually resolved rather than what a
registry would resolve today — and falls back to deps.dev.

## Supply-chain posture

deps.dev resolves each package to its source project and its OpenSSF Scorecard,
with no GitHub token and no local `scorecard` binary. That is what makes Dragon
Risk's supply-chain component scoreable at all; without it the 15% is
permanently excluded.

It surfaces the case the concept was built around — real risk with no CVE:

```
path-to-regexp@0.1.7
  CVSS 7.7, EPSS 0.008
  OpenSSF Scorecard 2.0/10        <- a top-three driver of the score
```

## Secret verification

Off by default. Enable per project:

```yaml
verify_secrets: true
```

Each detected credential is sent to its own issuer's read-only identity
endpoint — STS `GetCallerIdentity`, GitHub `/user`, Slack `auth.test` — to
establish whether it still authenticates. A verified-live credential is
escalated to critical with the identity it authenticates as; a rejected one
drops to medium, because it is still in the repository but it is not an
incident.

**The plaintext never leaves the scanning process.** Redaction is disabled only
while verifying, the value lives in memory for the length of one HTTPS call,
and only the verdict is attached to the finding. A findings database holding
live credentials would be a second breach waiting to happen.

Two details that matter:

- AWS needs both halves and detectors usually report only one, so the file the
  detection came from is scanned for the other half. Without that, AWS
  credentials — which leak as a pair in one file — are never verifiable.
- Anything other than an explicit 200 or 401/403 is **unknown**, never
  inactive. Guessing "inactive" from a rate limit is how a live production key
  gets filed as a false positive.

## What is and is not scanned

Findings in files `.gitignore` excludes are dropped before anything counts
them. A finding is a security problem because the code is *disclosed*, and a
gitignored file was never committed — so a credential in a developer's local
`.env` is not a disclosure, and reporting it as a critical one pushes real
findings off the page.

This is not hypothetical. On the first real repository DragonGuard was pointed
at, two of three "critical secrets" were a local `.env` and a gitignored
`.pem`. Together they tripped a gate that the one genuinely committed private
key had not.

Untracked-but-not-ignored files are kept: those are one `git add .` from being
disclosed, which is a warning rather than a non-event. The filtering is always
reported, never silent:

```
  ..  gitignore      2 finding(s) in gitignored files were excluded
                     (2 credential(s) — local only, not disclosed, but still on disk)
```

Set `scan_ignored_files: true` when the working tree itself is the artifact —
scanning a build context that gets `COPY`d into an image, for instance.

## Platform

`dragon push` submits results to a DragonGuard server, which scores them
against the organization's asset context and policy and returns the verdict:

```sh
export DRAGON_SERVER=https://guard.example.com/api/v1
export DRAGON_API_KEY=dgk_...
dragon push --project payments-api
```

The runner sends evidence; the server decides. It is running inside the change
being judged, so it does not get a say.

For GitHub, no runner is needed at all: install the App and every push to the
default branch and every pull request is scanned automatically, with the
verdict reported as a check run and inline annotations. See
[`DragonSecurity/dragonguard-platform`](../dragonguard-platform).

## Not yet built

- **Reachability for ecosystems beyond Go and Rust.** OSV-Scanner's call
  analysis supports those two; everything else scores as `unknown`.
- **Version-range remediation.** The dependency path is resolved and the
  direct dependency named, but the *version* of that direct dependency which
  first pulls in a fixed transitive is not computed — so the advice is
  "upgrade express", not "upgrade express to 4.18.2".
- **Container image scanning in the pipeline.** The Trivy adapter accepts an
  image target; the CLI does not yet expose it beyond `--image`.
- **Server-side scanning.** The platform evaluates submitted evidence rather
  than cloning repositories itself.

## Licence note

If this becomes a commercial service, review the licence of every engine,
ruleset and vulnerability feed independently. Semgrep is the cautionary
example: the CE engine remains LGPL while its maintained rules were relicensed
to restrict competing SaaS use.

## Using it as a library

The control plane is importable:

```go
import (
    "github.com/DragonSecurity/dragonguard/pkg/finding"
    "github.com/DragonSecurity/dragonguard/pkg/risk"
    "github.com/DragonSecurity/dragonguard/pkg/policy"
    "github.com/DragonSecurity/dragonguard/pkg/scorecard"
    "github.com/DragonSecurity/dragonguard/pkg/baseline"
)
```

The seams that make it embeddable rather than CLI-shaped:

- `baseline.Evaluate` takes the previous **scorecard**, not a file snapshot.
  The CLI reads it from disk and the platform reads it from Postgres, and the
  gate should not know which.
- `finding.MarkNew` takes a `map[fingerprint]firstSeen`, for the same reason.
- `policy.Engine.LoadRules` compiles rules from bytes, so a pack stored in a
  database goes through exactly the same validation as one committed to a repo.
