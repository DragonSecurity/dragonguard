# Configuring `.dragon.yaml`

`dragon init` writes a starter config. This is the full reference: every field,
what it changes, and the ones that are easy to get wrong.

The file is discovered by walking up from the working directory, looking for
`.dragon.yaml`, `.dragon.yml` or `dragon.yaml` in that order. `--config` points
at one explicitly. **A project with no config is not an error** — it gets
defaults, and the defaults assume production, because assuming otherwise
silently understates real risk on every unconfigured repository.

## A complete example

Every field below is optional except `version`. This example sets all of them
so there is one place to see them together; a real config is much shorter.

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

# ---------------------------------------------------------------------------
# Policy packs: files or directories. Relative paths resolve against this
# file's directory, and a directory is read recursively.
# ---------------------------------------------------------------------------
policies:
  - policies

# The baseline is the gate. Without one, a scan reports and never blocks.
baseline: .dragon-baseline.yaml

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
| `opengrep` | ruleset configs | Registry IDs (`p/security-audit`) or local paths. Multiple allowed. |
| `osv` | languages for call analysis | e.g. `[go, javascript]`. Not rulesets. |
| `zap` | `[target-url]` | One entry. Required — no target is ever inferred. |
| `schemathesis` | `[schema, base-url]` | **Two** entries, in that order. |
| `trivy` | *unused* | Configure it through `args`. |
| `gitleaks` | *unused* | Configure it through `args`. |

The two-entry requirement for `schemathesis` is the common mistake, because
`zap` next to it takes a single URL and the same shape reads as complete.
A one-entry `schemathesis` block is reported as such rather than skipped
silently.

Neither DAST engine will ever guess a target. Inferring one means sending
traffic somewhere nobody authorised, and doing that on a `production` asset is
worse than not scanning.

Both DAST engines fall back to their official container when the CLI is not on
`PATH` — `ghcr.io/zaproxy/zaproxy:stable` and `schemathesis/schemathesis:stable`
— so `docker` alone is enough to make them available. The other four engines
are `PATH`-only; see the README for why. One consequence: `localhost` inside a
container is the container, so a target pointing at a service on your own host
will not resolve through the fallback.

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

## The baseline is a separate file

`.dragon.yaml` describes what is being scanned. `.dragon-baseline.yaml`
describes what is acceptable, and it is the file that decides whether a build
passes. `dragon init` writes both. See `dragon baseline --help`, and
`dragon scan --record` to capture where a project currently sits before
setting a floor.

A floor guessed in advance is a floor somebody disables in a week. Run a few
scans first, then set one just below where you actually are, and raise it.

## Validation, and why it is strict

`asset.environment` and `asset.criticality` are checked against their allowed
values and a typo is rejected outright rather than ignored. A misspelled
`prodution` that quietly reads as "not production" would downgrade every
finding in the repository — which is exactly the failure this tool exists to
prevent.
