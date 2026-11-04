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
	Name      string   `yaml:"name" json:"name"`
	Actions   []string `yaml:"actions" json:"actions"`
	Audiences []string `yaml:"audiences" json:"audiences"`
	// Voice names the runtime that room admission creates grants for.
	Voice bool `yaml:"voice" json:"voice"`
	// Optional lets auth-server start without the runtime's account, for a
	// service only some deployments run. Without one, it simply can't sign in.
	Optional bool `yaml:"optional" json:"optional,omitempty"`
	// ToolAudience is the tool gateway's audience. Where the gateway runs,
	// AUTH_TOOL_GATEWAY makes it the only audience on tokens minted for this
	// runtime's grants, so the harness can't call a module without the gateway.
	// The grant keeps its own audiences, which the gateway exchanges the token
	// for. Elsewhere, as in Light, a token carries the grant's audiences.
	ToolAudience string `yaml:"tool_audience" json:"tool_audience,omitempty"`
}

// LoadExchangers reads which services may exchange a delegated token for one
// with another audience: the tool gateway, and nothing else.
func LoadExchangers(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read exchangers: %w", err)
	}
	var doc struct {
		Exchangers []string `yaml:"exchangers"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse exchangers: %w", err)
	}
	for _, name := range doc.Exchangers {
		if !namePattern.MatchString(name) {
			return nil, fmt.Errorf("exchanger %q is not a service name", name)
		}
	}
	return doc.Exchangers, nil
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
		// The gateway reads the grant's chain, so it has to be listed on it.
		if r.ToolAudience != "" && !slices.Contains(r.Audiences, r.ToolAudience) {
			return fmt.Errorf("runtime %s: tool_audience %q must also be one of its audiences", r.Name, r.ToolAudience)
		}
	}
	return nil
}

// Runtimes lists the reviewed runtimes, for the platform console, which checks
// each pool's audience against them.
func (s *Service) Runtimes() []Runtime { return slices.Clone(s.runtimes) }

// runtimeByID is the runtime a service account ID names.
func (s *Service) runtimeByID(id string) (Runtime, bool) {
	return s.runtime(strings.TrimPrefix(id, "svc_"))
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
