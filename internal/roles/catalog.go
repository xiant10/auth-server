// Package roles holds tenant-defined business roles: the permission catalog the
// deployed modules declare, the roles a tenant admin builds from it, their
// assignment to members, and the entitlement read modules check on each
// request. Built-in tenant and platform administration stay in directory; a
// role's name confers nothing.
package roles

import (
	"bytes"
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Lifecycles of a permission. A deprecated one still works but can't be added
// to a role; a retired one confers nothing.
const (
	LifecycleActive     = "active"
	LifecycleDeprecated = "deprecated"
	LifecycleRetired    = "retired"
)

var (
	modulePattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	prefixPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
	servicePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	keyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
	templatePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	appPathPattern  = regexp.MustCompile(`^[a-z0-9-]+(/[a-z0-9-]+)*$`)
)

// Permission is one action a module lets a role grant.
type Permission struct {
	Key         string `yaml:"key" json:"key"`
	Description string `yaml:"description" json:"description"`
	Lifecycle   string `yaml:"lifecycle" json:"lifecycle"`
}

// Template is a role a module suggests. Tenants create roles from it; a later
// version never changes a role already made.
type Template struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Permissions []string `yaml:"permissions" json:"permissions"`
}

// Module is one deployed module's catalog file.
type Module struct {
	ID string `yaml:"module" json:"id"`
	// Prefix is the namespace of every key, the module's action_prefix.
	Prefix string `yaml:"prefix" json:"prefix"`
	// Service is the only service account that may read this namespace's
	// entitlements. It defaults to t10-<module>.
	Service     string       `yaml:"service" json:"-"`
	Version     int          `yaml:"version" json:"version"`
	Permissions []Permission `yaml:"permissions" json:"permissions"`
	Templates   []Template   `yaml:"templates" json:"templates"`
	// App, when set, offers the module as a place on the landing page, to people
	// holding a role in it and to tenant admins.
	App *App `yaml:"app" json:"-"`
}

// App is how the landing page names a module and where it links. Path is under a
// tenant in workbench, which is where a module's screens live today.
type App struct {
	Path          string `yaml:"path"`
	Label         string `yaml:"label"`
	LabelZH       string `yaml:"label_zh"`
	Description   string `yaml:"description"`
	DescriptionZH string `yaml:"description_zh"`
}

// Catalog is what this environment deploys. A module missing from it is
// unavailable: its permissions confer nothing, and tenants' roles keep them.
type Catalog struct {
	modules []Module
	byKey   map[string]Permission
}

// LoadCatalog reads every <module>.yaml in dir, the mounted ConfigMap. An empty
// dir means no module declares business roles.
func LoadCatalog(dir string) (*Catalog, error) {
	if dir == "" {
		return NewCatalog(nil)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("list permission catalog: %w", err)
	}
	var modules []Module
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read permission catalog: %w", err)
		}
		var m Module
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&m); err != nil {
			return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
		}
		if want := m.ID + ".yaml"; filepath.Base(path) != want {
			return nil, fmt.Errorf("%s declares module %q, so it must be named %s", filepath.Base(path), m.ID, want)
		}
		modules = append(modules, m)
	}
	return NewCatalog(modules)
}

// NewCatalog validates modules and indexes them.
func NewCatalog(modules []Module) (*Catalog, error) {
	c := &Catalog{byKey: map[string]Permission{}}
	ids, prefixes := map[string]bool{}, map[string]bool{}
	for _, m := range modules {
		m.Service = cmp.Or(m.Service, "t10-"+m.ID)
		if err := validateModule(m); err != nil {
			return nil, err
		}
		if ids[m.ID] || prefixes[m.Prefix] {
			return nil, fmt.Errorf("module %s: module or prefix %q is declared twice", m.ID, m.Prefix)
		}
		ids[m.ID], prefixes[m.Prefix] = true, true
		for _, p := range m.Permissions {
			c.byKey[p.Key] = p
		}
		c.modules = append(c.modules, m)
	}
	slices.SortFunc(c.modules, func(a, b Module) int { return cmp.Compare(a.ID, b.ID) })
	return c, nil
}

func validateModule(m Module) error {
	switch {
	case !modulePattern.MatchString(m.ID):
		return fmt.Errorf("module %q: invalid module ID", m.ID)
	case !prefixPattern.MatchString(m.Prefix):
		return fmt.Errorf("module %s: invalid prefix %q", m.ID, m.Prefix)
	case !servicePattern.MatchString(m.Service):
		return fmt.Errorf("module %s: invalid service %q", m.ID, m.Service)
	case m.Version < 1:
		return fmt.Errorf("module %s: version must be at least 1", m.ID)
	case m.App != nil && (!appPathPattern.MatchString(m.App.Path) || m.App.Label == "" || m.App.LabelZH == ""):
		return fmt.Errorf("module %s: an app needs a relative path and a label in each language", m.ID)
	case len(m.Permissions) == 0:
		return fmt.Errorf("module %s: no permissions", m.ID)
	}
	keys := map[string]Permission{}
	for _, p := range m.Permissions {
		// A module can only ever define its own namespace, so it can't grant
		// another module's actions.
		if !keyPattern.MatchString(p.Key) || !strings.HasPrefix(p.Key, m.Prefix+":") {
			return fmt.Errorf("module %s: permission %q must be %s:<action>", m.ID, p.Key, m.Prefix)
		}
		if _, dup := keys[p.Key]; dup {
			return fmt.Errorf("module %s: permission %s is declared twice", m.ID, p.Key)
		}
		if !slices.Contains([]string{LifecycleActive, LifecycleDeprecated, LifecycleRetired}, p.Lifecycle) {
			return fmt.Errorf("module %s: permission %s has lifecycle %q", m.ID, p.Key, p.Lifecycle)
		}
		keys[p.Key] = p
	}
	seen := map[string]bool{}
	for _, t := range m.Templates {
		if !templatePattern.MatchString(t.ID) || seen[t.ID] || strings.TrimSpace(t.Name) == "" {
			return fmt.Errorf("module %s: template %q is invalid or repeated", m.ID, t.ID)
		}
		seen[t.ID] = true
		for _, key := range t.Permissions {
			p, ok := keys[key]
			if !ok || p.Lifecycle != LifecycleActive {
				return fmt.Errorf("module %s: template %s uses %q, which isn't an active permission of this module", m.ID, t.ID, key)
			}
		}
	}
	return nil
}

// Modules lists the deployed modules, by ID.
func (c *Catalog) Modules() []Module { return append([]Module{}, c.modules...) }

// Module returns one deployed module.
func (c *Catalog) Module(id string) (Module, bool) {
	i := slices.IndexFunc(c.modules, func(m Module) bool { return m.ID == id })
	if i < 0 {
		return Module{}, false
	}
	return c.modules[i], true
}

// Grants reports whether a key confers anything here: its module is deployed
// and it isn't retired.
func (c *Catalog) Grants(key string) bool {
	p, ok := c.byKey[key]
	return ok && p.Lifecycle != LifecycleRetired
}

// Assignable reports whether a key may be added to a role.
func (c *Catalog) Assignable(key string) bool {
	p, ok := c.byKey[key]
	return ok && p.Lifecycle == LifecycleActive
}

// moduleOf is the deployed module that owns a key's namespace.
func (c *Catalog) moduleOf(key string) (Module, bool) {
	prefix, _, _ := strings.Cut(key, ":")
	i := slices.IndexFunc(c.modules, func(m Module) bool { return m.Prefix == prefix })
	if i < 0 {
		return Module{}, false
	}
	return c.modules[i], true
}

// template returns one module's template.
func (c *Catalog) template(moduleID, id string) (Module, Template, bool) {
	m, ok := c.Module(moduleID)
	if !ok {
		return Module{}, Template{}, false
	}
	i := slices.IndexFunc(m.Templates, func(t Template) bool { return t.ID == id })
	if i < 0 {
		return Module{}, Template{}, false
	}
	return m, m.Templates[i], true
}
