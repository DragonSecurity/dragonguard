# The credential fixture

`config.env` is written here by the corpus test and removed afterwards. It is
gitignored, so it cannot be committed by accident.

It holds a randomly generated AWS key pair, issued by nobody, that
authenticates to nothing -- but it is shaped like a real one, because a
detector that skips it proves nothing. That tension is unavoidable: the only
credential a scanner will flag is one that resembles a credential. Generating
it per run means the resemblance never has to be permanent.

Both halves are written deliberately. Gitleaks does not flag the access key ID
on its own, and is right not to -- an ID identifies, it does not authenticate.
Trivy flags both. Asserting each separately is what catches either engine
narrowing what it looks for.
