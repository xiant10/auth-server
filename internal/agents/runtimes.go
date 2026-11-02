package agents

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// audienceT10 marks user tokens. A grant may never carry it, or an agent's
// token would pass as a user's at every service.
const audienceT10 = "t10"

var (
	namePattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(:[a-z][a-z0-9_-]*)+$`)
)

// Runtime is one entry of the reviewed runtime list: what a stable service may
// ask for on behalf of a user. Credentials live in the database, not here.
type Runtime struct {
	Name      string   `yaml:"name"`
	Actions   []string `yaml:"actions"`
	Audiences []string `yaml:"audiences"`
	// Voice names the runtime that room admission creates grants for.
	Voice bool `yaml:"voice"`
}

// LoadRuntimes reads and validates the runtime list from the clients file.
func LoadRuntimes(path string) ([]Runtime, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read runtimes: %w", err)
	}
	var doc struct {
		Runtimes []Runtime `yaml:"runtimes"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse runtimes: %w", err)
	}
	return doc.Runtimes, validateRuntimes(doc.Runtimes)
}

func validateRuntimes(runtimes []Runtime) error {
	seen := map[string]bool{}
	voice := false
	for _, r := range runtimes {
		if !namePattern.MatchString(r.Name) || seen[r.Name] {
			return fmt.Errorf("runtime name %q is invalid or repeated", r.Name)
		}
		seen[r.Name] = true
		if r.Voice && voice {
			return fmt.Errorf("runtime %s: only one runtime can serve voice", r.Name)
		}
		voice = voice || r.Voice
		if len(r.Actions) == 0 || len(r.Audiences) == 0 {
			return fmt.Errorf("runtime %s: actions and audiences are required", r.Name)
		}
		for _, action := range r.Actions {
			if !actionPattern.MatchString(action) {
				return fmt.Errorf("runtime %s: action %q must be an explicit name, with no wildcard", r.Name, action)
			}
		}
		for _, audience := range r.Audiences {
			if audience == audienceT10 || !namePattern.MatchString(audience) {
				return fmt.Errorf("runtime %s: audience %q is not allowed", r.Name, audience)
			}
		}
	}
	return nil
}

func (s *Service) runtime(name string) (Runtime, bool) {
	i := slices.IndexFunc(s.runtimes, func(r Runtime) bool { return r.Name == name })
	if i < 0 {
		return Runtime{}, false
	}
	return s.runtimes[i], true
}

func (s *Service) voiceRuntime() (Runtime, bool) {
	i := slices.IndexFunc(s.runtimes, func(r Runtime) bool { return r.Voice })
	if i < 0 {
		return Runtime{}, false
	}
	return s.runtimes[i], true
}

func subset(items, allowed []string) bool {
	return !slices.ContainsFunc(items, func(item string) bool { return !slices.Contains(allowed, item) })
}

// ServiceID is the ID a service account with this name holds.
func ServiceID(name string) string { return "svc_" + name }

// scopeOf is what a delegated token says it may do.
func scopeOf(actions []string) string { return strings.Join(actions, " ") }
