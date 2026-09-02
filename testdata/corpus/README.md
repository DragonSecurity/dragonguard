# The regression corpus

Every file here is deliberately broken, and each is named for the detection it
exists to prove still works.

This is not a test of the code under it. It is a test of **the engines**: when
Renovate bumps trivy or opengrep, this corpus is what says whether the new
version still finds what the old one found. A scanner that quietly stops
detecting something is the one failure a security gate cannot catch about
itself -- every downstream gate keeps passing, and nothing anywhere reports
that the floor moved.

`expected.yaml` records what must still be found. The check is deliberately
asymmetric:

- a detection that **disappeared** fails the build -- that is a regression
- detections that are **new** are reported, not failed -- that is the engine
  getting better, and a human decides whether to record it

Nothing here is ever built, imported or executed. Go ignores `testdata`
entirely, and the repository's own `.dragon.yaml` excludes this directory so
these fixtures do not appear in DragonGuard's own findings.

## The credential fixture is generated, never committed

`secrets/config.env` is written by the test and removed afterwards, and it is
gitignored so it cannot be committed by accident.

The first version of this corpus did commit it, and CI showed why that was
wrong: gitleaks scans git *history*, so the fixture came back as a critical
finding on a run where the local scan had been clean. Excluding it by path
does not help -- the path filter applies to the working tree, and history is
not the working tree. A plausible credential committed once is then found by
every future scan of this repository, by GitHub's own secret scanning, and by
anyone who clones it.

The key still has to *look* real, because a detector that skips it proves
nothing. That tension is unavoidable in a secrets fixture: the only credential
a scanner will flag is one that resembles a credential. Generating it per run
is what keeps the resemblance temporary.

`.dragon.yaml` here sets `scan_ignored_files`, so being gitignored does not
stop the corpus scan from seeing it -- uncommittable, but still scanned.
