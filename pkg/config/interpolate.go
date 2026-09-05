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

// interpolate replaces ${VAR} references with the environment's values.
//
// An unset variable with no default is an error, not an empty string. Empty
// would produce `Authorization: Bearer ` -- a header that is present, wrong,
// and indistinguishable from an authenticated scan until somebody reads the
// findings and wonders why everything behind the login looks clean. Leaving
// the reference in place is no better: it sends the literal "${DAST_TOKEN}".
//
// A project that genuinely wants an optional value says so with ${VAR:-} and
// means it.
func interpolate(raw []byte) ([]byte, error) {
	const placeholder = "\x00dragonguard-literal-dollar-brace\x00"
	text := strings.ReplaceAll(string(raw), escapedDollar, placeholder)

	missing := map[string]bool{}
	out := envReference.ReplaceAllStringFunc(text, func(ref string) string {
		m := envReference.FindStringSubmatch(ref)
		name, hasDefault, fallback := m[1], m[2] != "", m[3]

		if v, ok := os.LookupEnv(name); ok && v != "" {
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
