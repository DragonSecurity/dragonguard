# Configuring `.dragon.yaml`

`dragon init` writes a starter config. This is the full reference: every field,
what it changes, and the ones that are easy to get wrong.

The file is discovered by walking up from the working directory, looking for
`.dragon.yaml`, `.dragon.yml` or `dragon.yaml` in that order. `--config` points
at one explicitly. **A project with no config is not an error** — it gets
defaults, and the defaults assume production, because assuming otherwise
silently understates real risk on every unconfigured repository.

## A complete example

Every field below is optional except `version`. This example sets **all** of
them, uncommented and at the indentation they actually take, so there is one
place to see both what exists and where it goes; a real config is much shorter.

The top-level keys are `version`, `project`, `asset`, `engines`, `policies`,
`baseline`, `default_branch`, `licenses`, `accept`, `ships`, `dast`,
`supply_chain`, `ignore`, `state_dir`, and the switches at the end. Anything not in that list belongs
inside one of them.

```yaml
version: dragonguard/v1
project: dragonguard-platform

# ---------------------------------------------------------------------------
# Asset context
#
# This is the part that matters most and takes the least time to fill in. It
# is what separates "CVSS 9.8" from "fix this today": the same vulnerability
# in an internet-facing payments service and in a developer's scratch tool is
# not the same problem, and a scanner that cannot tell them apart ranks them
# the same.
# ---------------------------------------------------------------------------
asset:
  name: dragonguard-platform          # defaults to `project`
  environment: production             # production | staging | development | test
  criticality: critical               # critical | high | medium | low
  internet_exposed: true              # reachable by an unauthenticated attacker?
  handles_pii: true                   # raises the cost of a breach
  handles_payments: false
  owner: platform-team                # free text; travels with every finding
  tags: [control-plane, multi-tenant]

# ---------------------------------------------------------------------------
# Engines
#
# Keyed by engine name. A missing engine degrades a scan rather than failing
# it -- `dragon engines` reports which dimensions your gate is currently blind
# to. Every engine takes the same four keys, but `rules` means something
# different in each; see the table below.
# ---------------------------------------------------------------------------
engines:
  trivy:
    enabled: true
    args: ["--severity", "MEDIUM,HIGH,CRITICAL"]
    timeout: 300                      # seconds; 0 or unset means the engine default

  opengrep:
    enabled: true
    rules:                            # OpenGrep configs: registry IDs or local paths
      - builtin                       # DragonGuard's own pack; see below
      - p/security-audit
      - ./rules

  gitleaks:
    enabled: true

  osv:
    enabled: true
    rules: [go, javascript]           # languages to run call analysis for

  zap:
    enabled: true
    rules:
      - https://staging.example.com/  # the single target URL. Required.

  schemathesis:
    enabled: true
    rules:
      - https://staging.example.com/api/v1/openapi.json   # the schema
      - https://staging.example.com/api/v1                # the base URL

  supplychain:
    enabled: true                     # no binary; it queries deps.dev

# ---------------------------------------------------------------------------
# Policy packs: files or directories. Relative paths resolve against this
# file's directory, and a directory is read recursively.
# ---------------------------------------------------------------------------
policies:
  - policies

# The baseline is the gate. Without one, a scan reports and never blocks.
baseline: .dragon-baseline.yaml

# The branch the regression gate compares against. Detected when unset:
# origin/HEAD, then a local main or master. See "What the regression gate
# compares against" below.
default_branch: main

# ---------------------------------------------------------------------------
# Standing decisions about dependency licences. Top level, not under an
# engine: the decision is the project's, and it holds whichever engine
# reported the licence. Every entry needs a reason -- see "Approving a
# licence" below for why that is required rather than optional.
# ---------------------------------------------------------------------------
licenses:
  allow:
    - id: MPL-2.0
      reason: >-
        Consumed unmodified. The obligation attaches to modified MPL files and
        we vendor and patch none of them. Revisit if any is ever forked.
      approved_by: the security team
  deny:
    - id: AGPL-3.0
      reason: We ship a hosted service; the network clause is not acceptable here.
      approved_by: the security team

# ---------------------------------------------------------------------------
# Findings this project has decided to carry rather than fix. Distinct from
# ignore: below, which is about paths that were never in scope -- an
# acceptance is about a finding that is real, in scope, and staying. It stays
# in the report, marked, and stops counting. See "Accepting a finding you are
# not going to fix" below.
# ---------------------------------------------------------------------------
accept:
  - finding: GO-2026-5932
    reason: >-
      openpgp is unmaintained upstream with no replacement, and we neither
      sign nor verify PGP. Nothing to upgrade to.
    approved_by: the security team
  - package: github.com/spf13/viper
    finding: supply-chain/weak-upstream
    reason: Reviewed 2026-09; Scorecard measures process, not this library's risk.
    approved_by: the security team
    expires: 2027-03-01

# ---------------------------------------------------------------------------
# What the dynamic engines need to get past a login. One block for both: ZAP
# and Schemathesis hit the same API and need the same credential, and express
# it completely differently. See "Scanning behind a login" below.
#
# A dollar-brace reference reads the environment. Never write a credential
# here directly -- this file is committed, and DragonGuard's own secret
# scanner will flag it.
# ---------------------------------------------------------------------------
dast:
  headers:
    Authorization: "Bearer ${DAST_TOKEN}"

# The packages this project actually ships, as `go list` patterns. Go is the
# only ecosystem that does not record which dependencies are build-only, so
# naming the entry points is what lets the toolchain work it out. See "Which
# Go dependencies actually ship" below.
ships:
  - .
  - ./cmd/...

# Where the upstream-posture engine draws its lines. These are the defaults;
# see "Tuning the supply-chain engine" below.
supply_chain:
  min_scorecard: 4.0
  quiet_below: 5.0

# Path globs excluded from every engine. See "What ignore: actually
# excludes" below for how a pattern is matched.
ignore:
  - node_modules
  - vendor
  - .git

# Previous scorecards live here; the regression gate needs them to know
# whether posture went down. Commit the baseline, not this directory.
state_dir: .dragon

# ---------------------------------------------------------------------------
# Switches that change what a scan is allowed to do. All default to false.
# ---------------------------------------------------------------------------

# Disable every network call, including the EPSS and KEV refresh. The gate
# then runs on cached intelligence, and reports itself as degraded if there
# is none.
offline: false

# Include findings from files .gitignore excludes.
#
# Off by default, and the default is the considered position: a finding is a
# security problem because the code is disclosed, and a gitignored file was
# never committed. A credential in a developer's local .env is not a
# disclosure, and reporting it as a critical one pushes real findings off the
# page. Turn it on when the working tree itself is the artifact -- scanning a
# build context that is about to be COPYed into an image, for instance.
scan_ignored_files: false

# Verify detected secrets against their own issuer's read-only identity
# endpoint, to establish whether they still authenticate. The plaintext never
# leaves the scanning process and is never stored; only the verdict is
# attached to the finding. Off by default because it makes a scan send
# credentials over the network, which is a decision to take deliberately.
verify_secrets: false
```

## What `rules` means, per engine

There is one `rules` field and five meanings, which is the config's sharpest
edge. It exists because inventing a bespoke config shape per engine costs more
than it saves — but it does mean copying a `rules` block between engines
produces something that parses and is wrong.

| Engine | `rules` is | Notes |
| --- | --- | --- |
| `opengrep` | ruleset configs | Registry IDs (`p/security-audit`), local paths, or `builtin`. Multiple allowed. |
| `osv` | languages for call analysis | e.g. `[go, javascript]`. Not rulesets. |
| `zap` | `[target-url]` | One entry. Required — no target is ever inferred. |
| `schemathesis` | `[schema, base-url]` | **Two** entries, in that order. |
| `trivy` | *unused* | Configure it through `args`. |
| `gitleaks` | *unused* | Configure it through `args`. |
| `supplychain` | *unused* | Tuned through the top-level `supply_chain:` block. |

The two-entry requirement for `schemathesis` is the common mistake, because
`zap` next to it takes a single URL and the same shape reads as complete.
A one-entry `schemathesis` block is reported as such rather than skipped
silently.

Neither DAST engine will ever guess a target. Inferring one means sending
traffic somewhere nobody authorised, and doing that on a `production` asset is
worse than not scanning.

Both DAST engines fall back to their official container when no CLI is on
`PATH` — `ghcr.io/zaproxy/zaproxy:stable` and `schemathesis/schemathesis:stable`
— so `docker` alone is enough to make them available. Schemathesis is looked up
under **both** the names it installs as, `schemathesis` and `st`; finding
either one skips the container.

One consequence of the fallback: `localhost` inside a container is the
container, so a target pointing at a service on your own host will not resolve
through it.

Of the remaining five engines, four are `PATH`-only — `trivy`, `opengrep`,
`gitleaks`, `osv` — and see the README for why. `supplychain` needs no binary at
all: it reads the inventory the others resolved and asks deps.dev about the
projects behind it, so what makes it unavailable is `offline: true`, or a scan
where nothing resolved an inventory for it to assess.

## `enabled` and the shape of an engine block

`enabled` defaults to **true** when the key is present but unset, so:

```yaml
engines:
  trivy: {enabled: true}    # explicit
  gitleaks: {}              # also enabled
  osv:
    enabled: false          # the only way to turn one off
```

An engine that is absent from `engines` entirely still runs. The map tunes
engines; it is not an allowlist.

## What `ignore:` actually excludes

A pattern with **no `/`** matches any single path segment, at any depth. So
`node_modules` covers `ui/node_modules/react/index.js`, which is what anyone
writing it means.

A pattern **containing `/`** is anchored at the scan root and matches that path
exactly, or anything beneath it:

```yaml
ignore:
  - internal/migrations/tenant            # the directory and everything in it
  - internal/migrations/tenant/atlas.sum  # just the one file
```

Anchoring is deliberate. An unanchored `docs/build` would also match
`ui/vendor/docs/build`, and a rule that quietly excludes more than it names is
how a finding ends up hidden from someone who does not know it is hidden.

`*` and `?` glob within a segment; `**` spans zero or more segments.

The list is applied to the findings **every** engine returns, not only to the
engines whose command line has a suitable exclude flag. Trivy, OpenGrep and OSV
are each given the list as a flag because it saves them the work, but Gitleaks
has no such flag and `--skip-dirs` cannot exclude a single file. Enforcing the
list centrally is what makes it mean the same thing for every engine, and for
the next engine added.

Anything excluded this way is counted in the scan output on an `ignore` line,
for the same reason gitignored findings are: a filter you cannot see is
indistinguishable from a scanner that missed something.

## Approving a licence

A scan reports dependency licences that carry an obligation — copyleft,
reciprocal, forbidden, and anything it cannot classify. Permissive and
attribution-only licences are dropped, because a gate that reports every MIT
dependency teaches people that the licence dimension is noise.

An obligation reported is not an obligation incurred. MPL-2.0 is the common
case: it is *file-level* copyleft, so the obligation attaches to MPL-licensed
files that are themselves modified. Consuming a library unmodified triggers
nothing — but a scanner cannot see the difference between consuming and
vendoring-then-patching, so it reports both.

That decision belongs in the repository:

```yaml
licenses:
  allow:
    - id: MPL-2.0
      reason: >-
        Consumed unmodified. The obligation attaches to modified MPL files and
        we vendor and patch none of them. Revisit if any is ever forked.
      approved_by: the security team
  deny:
    - id: AGPL-3.0
      reason: We ship a hosted service; the network clause is not acceptable here.
      approved_by: the security team
```

An approved licence's findings stop counting against the `dependencies` score.
A denied licence fails the gate whatever the scanner made of it.

`approved_by` is optional here and required on `accept:` below. The
inconsistency is deliberate: this field was added to a surface projects already
use, and requiring it would have failed every existing config on upgrade. Write
it anyway — a standing exception whose author cannot be found is one nobody is
willing to revisit.

**The reason is required, not optional.** A bare list of approved identifiers
records the conclusion and loses the reasoning, so when somebody later forks
that dependency, nothing reopens the question. The reason is the only part of
the decision that survives the person who made it, and it is shown as the
rule's description in the policy evaluations.

Identifiers are matched exactly as the scanner reports them — normally SPDX:
`MPL-2.0`, `BlueOak-1.0.0`, `Apache-2.0 WITH LLVM-exception`.

### The same thing in a policy rule

`licenses:` is desugared into ordinary Dragon Policy rules, so there is one
evaluation path and the approvals appear in the policy evaluations like
anything else. Anything more conditional than a list is written directly:

```yaml
- id: reciprocal-is-fine-outside-production
  when: finding.license_category == "reciprocal" && asset.environment != "production"
  then:
    decision: allow
    exempt: true
```

`finding.license` and `finding.license_category` are empty strings for findings
that are not about a licence, so a rule using them never errors — it simply
does not match.

## Accepting a finding you are not going to fix

Some findings cannot be closed. `GO-2026-5932` says
`golang.org/x/crypto/openpgp` is unmaintained: there is no fixed version, no
replacement, and no amount of upgrading makes it go away. Others could be
closed and should not be — an upstream project with a weak OpenSSF Scorecard is
usually a small library that does one thing correctly, not a risk.

Before `accept:`, the only controls for either were to turn the engine off or
to add the path to `ignore:`, and both of those say something untrue. Turning
the engine off stops looking. `ignore:` claims the path was never in scope.

```yaml
accept:
  - finding: GO-2026-5932
    reason: >-
      openpgp is unmaintained upstream with no replacement, and we neither sign
      nor verify PGP. Nothing to upgrade to.
    approved_by: the security team

  - package: github.com/spf13/viper
    finding: supply-chain/weak-upstream
    reason: >-
      Reviewed 2026-09. Scorecard measures process, and this is a stable config
      library we read before adopting.
    approved_by: the security team
    expires: 2027-03-01
```

An accepted finding **stays in the report**, marked `accepted`, and stops
counting against the score and the gate. It is not deleted, for the reason
every other filter here reports itself: a suppression nobody can see is
indistinguishable from a scanner that stopped looking. The scan prints an
`accepted` line saying how many entries are in force and how many findings they
matched — and if that second number is zero, the register has outlived the
findings it was written for.

### Selectors

| Field | Matches |
| --- | --- |
| `finding` | an advisory id (`GO-2026-5932`, `GHSA-…`), a CVE, or an engine rule id (`supply-chain/weak-upstream`) |
| `package` | a dependency, as `name` or as the `name@version` the report prints |
| `fingerprint` | **one specific finding**, in full or abbreviated to at least 8 characters |

At least one is required. Give several and they must all match, which is how
you accept one advisory *in one dependency* rather than everywhere it appears.

`finding` matches the rule id **or** any CVE on the finding, because which
identifier a finding carries depends on the engine that reported it and you
should not have to know which one ran.

`package` accepts either form, because the report identifies a dependency as
`next-themes@0.4.6` and that is what anyone writing an acceptance copies:

```yaml
- package: next-themes            # any version
- package: next-themes@0.4.6      # that version only
- package: github.com/spf13/viper@v1.21.0   # the v is optional either way
```

Naming a version narrows the entry to it, which is usually right — a review was
of what was there, and the next bump is worth seeing. Omit it to accept the
dependency however it moves.

### `fingerprint` accepts one finding, not a whole rule

`finding:` matches a **rule**, which for a DAST result is almost never what
somebody means. Accepting a schema check that is wrong about `/auth/login` also
silences it on `/auth/{provider}/callback` — an endpoint nobody reviewed, whose
next real failure now goes unreported.

`fingerprint:` names the occurrence:

```yaml
- fingerprint: 09c9d574
  expires: 2027-03-05
  reason: >-
    POST /auth/login answers 429 once an account passes ten failed attempts,
    and the checker does not accept 429 for schema-compliant input. That is the
    brute-force lockout, not the rate limiter.
  approved_by: the security team
```

Abbreviations work, the way git taught everyone to expect, down to eight
characters — below that a prefix stops naming one finding and starts matching
whatever shares those digits.

Fingerprints are stable across scans as long as the finding is: they survive
the code moving down the file, reindentation, and the same advisory being
reported by a different engine. They are in the JSON report:

```sh
dragon scan --format json | jq -r '.findings[] | "\(.fingerprint)  \(.title)"'
```

### Which selector to use, and the trap in narrowing

`package:` alone accepts **any** finding about that dependency. That is usually
what "we reviewed this library and it is fine" means, and it keeps working when
the finding about it changes.

Adding `finding:` narrows the entry to one specific rule, and both must then
match. That is right when you have accepted one advisory in a dependency and
still want to hear about the next one — but it is easy to get wrong, because
**which supply-chain rule fires depends on the score, not on the dependency**:

| Score | Rule |
| --- | --- |
| below `min_scorecard` (default 4.0) | `supply-chain/weak-upstream` |
| between it and `quiet_below` (default 5.0), with no recent commits | `supply-chain/quiet` |

So a project accepting `supply-chain/weak-upstream` for four dependencies
scoring 2.9 to 3.7 sees all four accepted, and the fifth at 4.5 silently not —
because 4.5 is *above* the threshold and its finding is `supply-chain/quiet`.
The report shows a finding's title and never its rule id, so there is nothing
on screen to work that out from.

Two things follow. Prefer `package:` on its own unless you specifically mean
one rule. And when an entry is in force and matches nothing, the scan says so
by name:

```
  !!  accepted       1 acceptance(s) matched nothing: supply-chain/weak-upstream in github.com/spf13/viper
```

Named rather than counted, because the two causes want opposite responses: the
finding is genuinely gone and the entry can go with it, or the selector is
wrong and a decision somebody recorded is quietly not in effect.

### `reason` and `approved_by` are both required

Same argument as the licence reason, one step further. An exception silences a
real finding, so the two questions anyone will ask about it in a year are why,
and who decided. A register that answers neither is a register nobody dares
delete from.

### `expires` is what makes it a register and not a graveyard

```yaml
    expires: 2027-03-01
```

Optional, and the most useful field here. An acceptance is written against a
situation — no fix available yet, a dependency under review — and situations
change without reminding anyone to look.

Past the date the acceptance stops applying and the finding counts again, which
is the point. It is also **reported**, on a highlighted `accepted` line, rather
than being dropped in silence: a lapsed expiry that said nothing would look
exactly like the acceptance never having been written, and the first anyone
would know is a posture drop with no cause.

Acceptances are desugared into ordinary policy rules like `licenses:`, so
`approved_by` shows up as the rule's description and the whole register stays
auditable rather than becoming a second hidden mechanism.

## Which Go dependencies actually ship

npm has `dependencies` and `devDependencies`. Python has extras and dev groups.
Go has `require`, and nothing else: the code-generation tool imported by a
package under `tools/` sits in the same list as the database driver the server
opens at startup.

The problem was not that the information was missing. It was that its absence
was reported as a fact — every Go dependency arrived with `dev_only: false`,
which is a claim, not a gap. The built-in policy rule written for exactly this
case could therefore never fire:

```
accept-dev-only-medium-risk        allow
  when: ((component.dev_only) && (risk.score < 75))
```

And a service was scored for the whole GCP and Spanner tree that reaches it
only through a schema-generation tool it does not link.

The toolchain can answer this exactly, given the one thing only the project
knows — what it ships:

```yaml
ships:
  - .
  - ./cmd/...
```

Ordinary `go list` patterns. Everything outside the closure of those packages
is build-only *by construction*: this is the same graph the linker walks, not a
guess about directory names. On a mid-sized service it typically moves a third
to a half of the module list out of production scope.

`ships:` also decides the other direction. Name `./tools/...` there and its
dependencies are shipped, because the list says what this project ships rather
than encoding an opinion about what a directory called `tools` means.

### When it cannot be determined

Leave `ships:` unset and the scan says so, on a `ships` line in the evidence
block, instead of continuing to assert that everything reaches production. The
same line reports a `go list` that failed — a pattern matching no packages is an
error rather than an empty closure, because a typo that silently marked every
dependency build-only would take the dependency dimension with it.

Nothing is guessed when it is unset: findings keep the behaviour they had
before, and the rule above stays inert. The difference is that you can now see
that it is.

An offline scan runs `go list` with `GOPROXY=off`. If the module cache is
incomplete it fails and reports undetermined, which is the right outcome: a
closure computed from half a module cache would mark real dependencies
build-only, and that is the one mistake this must not make.

## Scanning behind a login

An unauthenticated DAST run against an authenticated API tests the login wall
and nothing behind it. It comes back with a couple of header findings and a
clean-looking score, which is worse than not running it: the coverage is
missing and the report does not say so.

Both engines need the same credential and neither would take one. Schemathesis
took raw `args` and ZAP took nothing at all, and there was nowhere safe to put
the value either way.

```yaml
dast:
  headers:
    Authorization: "Bearer ${DAST_TOKEN}"
    X-Tenant: acme
```

One block for both engines, because they are pointed at the same running API.
Each translates it into its own dialect: Schemathesis gets `-H`, and ZAP gets
its Replacer add-on configured — six numbered properties per header, which is
not something anybody should write by hand in a YAML file.

The scan says what it sent, by name and never by value:

```
  ..  dast auth      2 header(s) sent with every request: Authorization, X-Tenant
```

### `${VAR}` reads the environment

`.dragon.yaml` is committed. A credential written into it is a disclosed
credential whatever the reason, and this tool's own secret scanner will flag it
— correctly. So the file names the variable and CI carries the value.

`${VAR}` works anywhere a value does, not only in `dast`.

**An unset variable is an error, not an empty string.** `Authorization: Bearer `
is a header that is present, wrong, and indistinguishable from an authenticated
scan until somebody reads the findings and wonders why everything behind the
login looks clean. An exported-but-empty variable counts as unset, because that
is the usual shape of a secret that did not make it into CI. Every missing
variable is named at once, rather than one deploy at a time.

For a genuinely optional value, say so:

```yaml
    X-Debug: "${DEBUG_HEADER:-off}"
    X-Optional: "${MAYBE:-}"
```

Write `$${` for a literal `${`.

Substitution is textual and happens before the YAML is parsed, so a reference
inside a **comment** is resolved like any other — an unset variable mentioned in
passing will fail the load. Escape it, or write the name without the braces.

### Where the secret actually goes

ZAP's headers are written to a properties file beside the report and passed
with `-configfile`, not as `-config` pairs on the command line. Both work; only
one keeps a bearer token out of the process table, where anything else on the
runner can read it out of `ps`.

Schemathesis has no equivalent — `-H` is a command-line flag and that is the
only interface it offers — so on a shared machine its header is visible in the
process list for the duration of the run. Worth knowing before pointing it at
production credentials.

Neither value is ever written to a report, a scorecard or a SARIF file. Only
the header names are.

### `args` is still there

`engines.zap.args` and `engines.schemathesis.args` are appended after the
generated authentication, so an engine-specific flag can still be the last
word. Appended, not substituted: adding one unrelated flag must not silently
drop every header.

(`engines.zap.args` was previously read by nothing at all. It works now.)

## Tuning the supply-chain engine

The `supply_chain` dimension reports *upstream posture*: OpenSSF Scorecard and
publication activity for the dependencies your manifest names directly. Its two
thresholds are a judgement about a whole ecosystem, and a project knows its own
tree better than a constant does.

```yaml
supply_chain:
  min_scorecard: 4.0   # below this, a direct dependency is worth a decision
  quiet_below: 5.0     # below this, prolonged upstream silence is worth saying
```

Those are the defaults. `4.0` rather than something higher because most of the
ecosystem sits between four and seven, and a threshold that flags half the
dependency tree is a threshold nobody reads. Lower it if your tree is mostly
small finished libraries; raise it if you only take well-run upstreams.

An unset or empty `supply_chain:` block means the defaults, not silence.
Reading an omitted field as "flag nothing" would turn adding an empty block
into a coverage gap.

Nothing here gates. These findings are recorded at `info`, so the thresholds
change what is worth reading, not what blocks a release — the one exception
being `supply-chain/deprecated`, which is `high` and is not a threshold at all:
a publisher marking a version deprecated is a statement that it will not be
fixed.

For a decision about one specific dependency rather than about the whole
ecosystem, use `accept:` above.

## `rules:` replaces, it does not extend

Naming a ruleset for an engine replaces its default. That is deliberate -- a
project that says which rules it wants should get those rules -- but it has a
consequence worth stating outright: setting `engines.opengrep.rules` switches
DragonGuard's own pack **off**.

`builtin` is how you keep it:

```yaml
engines:
  opengrep:
    rules:
      - builtin           # DragonGuard's pack, embedded in the binary
      - p/security-audit  # and a registry pack alongside it
```

It needs a name because it has no path: the pack is extracted to a temporary
directory at scan time, so there is nothing stable to write in a config file.

The order is preserved, because OpenGrep applies configs in order.

**A scan says which sources it used**, in the evidence table, so this is never
a guess:

```
  OK  opengrep       6 findings in 3074ms
  ..                 rules: built-in pack, p/security-audit
```

With nothing configured it reads `built-in pack (engines.opengrep.rules not
set)` -- which is the answer to "why does running the engine by hand disagree
with the scan".

## What the regression gate compares against

The **default branch**, always -- not the branch being scanned.

The question a gate is asked on a pull request is *does merging this make main
worse*, and only main's baseline can answer it. A branch measured against its
own last scan answers a different question -- *is this worse than it was an
hour ago* -- which a branch that is already below main passes trivially. A
five-point drop against main reads as `+0` against itself, and
`maximum_regression: 3` never fires.

So `dragon scan` on a feature branch loads the snapshot recorded for the
default branch. `dragon scan --record` still writes a snapshot named after the
branch it ran on, and says so when that is not the default branch, because
recording on a feature branch looks like it has set the bar and does not.

When no snapshot exists for the default branch, every configured regression
rule is reported as `--  not evaluated: no baseline recorded` rather than as a
passing check. It does not block -- a first scan cannot regress -- but a
constraint that has never once run must not read as a green tick.

## The baseline is a separate file

`.dragon.yaml` describes what is being scanned. `.dragon-baseline.yaml`
describes what is acceptable, and it is the file that decides whether a build
passes. `dragon init` writes both. See `dragon baseline --help`, and
`dragon scan --record` to capture where a project currently sits before
setting a floor.

A floor guessed in advance is a floor somebody disables in a week. Run a few
scans first, then set one just below where you actually are, and raise it.

## A setting that does nothing now says so

YAML ignores a key it does not recognise, in silence. For a configuration file
that is the worst of the available behaviours, and it has two causes that look
identical from the outside:

- a typo — `licenses.alow`, `acccept`
- a block copied from the documentation of a **newer release** than the
  `dragon` binary actually running

In both cases the setting is plainly there in the file, the scan behaves
exactly as though it were absent, and nothing says which. That is an afternoon
spent on a block that was discarded at load.

So an unrecognised key is now reported, on a highlighted `config` line:

```
  !!  config         2 setting(s) this build does not understand were ignored: alow, teleport
```

**Reported, never refused.** Both causes want the same answer. Refusing would
mean a config written for a newer DragonGuard cannot run on an older one at
all, which turns a warning into an outage — and the version skew is exactly
when you most want the scan to still run.

If a setting you have written is listed there and is not a typo, check
`dragon version` against the release the setting was added in.

## Validation, and why it is strict

`asset.environment` and `asset.criticality` are checked against their allowed
values and a typo is rejected outright rather than ignored. A misspelled
`prodution` that quietly reads as "not production" would downgrade every
finding in the repository — which is exactly the failure this tool exists to
prevent.
