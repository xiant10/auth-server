package roles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func module(id, prefix string, keys ...string) Module {
	m := Module{ID: id, Prefix: prefix, Version: 1}
	for _, key := range keys {
		m.Permissions = append(m.Permissions, Permission{Key: key, Lifecycle: LifecycleActive})
	}
	return m
}

func TestCatalogHoldsEachModuleToItsNamespace(t *testing.T) {
	_, err := NewCatalog([]Module{module("deals", "deals", "deals:read", "crm:read")})
	if err == nil || !strings.Contains(err.Error(), "crm:read") {
		t.Errorf("foreign key accepted: %v", err)
	}
	_, err = NewCatalog([]Module{module("deals", "deals", "deals:read"), module("crm", "deals", "deals:write")})
	if err == nil {
		t.Error("two modules shared a prefix")
	}
	for _, key := range []string{"deals:*", "deals:", "deals:Read", "deals:read.", "deals"} {
		if _, err := NewCatalog([]Module{module("deals", "deals", key)}); err == nil {
			t.Errorf("key %q accepted", key)
		}
	}
}

func TestCatalogServiceDefaultsToTheModulesOwn(t *testing.T) {
	c, err := NewCatalog([]Module{module("property", "property", "property:read")})
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := c.Module("property"); m.Service != "t10-property" {
		t.Errorf("service = %q", m.Service)
	}
}

func TestTemplatesUseOnlyActivePermissions(t *testing.T) {
	m := module("deals", "deals", "deals:read")
	m.Permissions = append(m.Permissions, Permission{Key: "deals:old", Lifecycle: LifecycleDeprecated})
	m.Templates = []Template{{ID: "rep", Name: "Rep", Permissions: []string{"deals:old"}}}
	if _, err := NewCatalog([]Module{m}); err == nil {
		t.Error("template used a deprecated permission")
	}
	m.Templates = []Template{{ID: "rep", Name: "Rep", Permissions: []string{"crm:read"}}}
	if _, err := NewCatalog([]Module{m}); err == nil {
		t.Error("template used another module's permission")
	}
}

func TestLifecycles(t *testing.T) {
	m := module("deals", "deals", "deals:read")
	m.Permissions = append(m.Permissions,
		Permission{Key: "deals:old", Lifecycle: LifecycleDeprecated},
		Permission{Key: "deals:gone", Lifecycle: LifecycleRetired})
	c, err := NewCatalog([]Module{m})
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string][2]bool{
		"deals:read": {true, true}, "deals:old": {true, false}, "deals:gone": {false, false}, "crm:read": {false, false},
	} {
		if got := [2]bool{c.Grants(key), c.Assignable(key)}; got != want {
			t.Errorf("%s: grants, assignable = %v, want %v", key, got, want)
		}
	}
}

func TestLoadCatalogFileNameMustMatchModule(t *testing.T) {
	dir := t.TempDir()
	body := "module: deals\nprefix: deals\nversion: 1\npermissions:\n  - {key: deals:read, lifecycle: active}\n"
	if err := os.WriteFile(filepath.Join(dir, "crm.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(dir); err == nil {
		t.Error("crm.yaml declared deals")
	}
	if err := os.Rename(filepath.Join(dir, "crm.yaml"), filepath.Join(dir, "deals.yaml")); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCatalog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Grants("deals:read") {
		t.Error("deals:read missing")
	}
	if err := os.WriteFile(filepath.Join(dir, "deals.yaml"), []byte(body+"surprise: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(dir); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestEmptyDirMeansNoModules(t *testing.T) {
	c, err := LoadCatalog("")
	// Never nil, so the catalog answers [] rather than null.
	if err != nil || c.Modules() == nil || len(c.Modules()) != 0 {
		t.Errorf("modules %v, err %v", c.Modules(), err)
	}
}

func TestCatalogAppNeedsARelativePathAndBothLabels(t *testing.T) {
	base := Module{ID: "deals", Prefix: "deals", Version: 1, Permissions: []Permission{{Key: "deals:read", Description: "See", Lifecycle: LifecycleActive}}}
	for name, app := range map[string]App{
		"absolute URL": {Path: "https://evil.example", Label: "D", LabelZH: "交"},
		"parent path":  {Path: "../admin", Label: "D", LabelZH: "交"},
		"no label":     {Path: "deals", LabelZH: "交"},
		"no Chinese":   {Path: "deals", Label: "D"},
	} {
		m := base
		m.App = &app
		if _, err := NewCatalog([]Module{m}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	m := base
	m.App = &App{Path: "deals/home", Label: "D", LabelZH: "交"}
	if _, err := NewCatalog([]Module{m}); err != nil {
		t.Error(err)
	}
}
