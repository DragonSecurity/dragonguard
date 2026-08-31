# Dragon Rules

DragonGuard's own SAST rules, in Semgrep-format YAML, executed by OpenGrep.

## Why these exist

OpenGrep is a fork of Semgrep 1.100.0 and runs Semgrep-format rules unchanged.
Engine compatibility is not, however, permission to redistribute anybody's
ruleset: the OpenGrep engine is LGPL 2.1, while Semgrep-maintained rules carry
licence terms that restrict use in a competing hosted service.

So DragonGuard ships its own rules. They are deliberately few and deliberately
high-precision. A rule that fires on safe code costs more than it saves — the
first noisy gate is the last gate a team pays attention to.

Point the engine somewhere else any time:

```yaml
engines:
  opengrep:
    rules:
      - ./rules              # these
      - p/security-audit     # a registry pack, subject to its own licence
      - ./my-org-rules       # your own
```

## Adding a rule

Every rule must carry `metadata.cwe` and `metadata.severity`. The adapter reads
both: CWE lands on the finding, and severity feeds Dragon Risk. A rule without
them still runs, but scores as a generic medium, which is rarely what you want.
