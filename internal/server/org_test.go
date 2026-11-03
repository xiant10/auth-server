package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"t10-auth-server/internal/directory"
)

func (h *harness) orgUsers(names ...string) map[string]string {
	h.t.Helper()
	h.tenant("ten_acme")
	users := map[string]string{}
	for _, name := range names {
		users[name] = h.user(name, map[string]string{"ten_acme": directory.RoleMember})
	}
	return users
}

func (h *harness) place(user, manager, unit string) error {
	h.t.Helper()
	return h.dir.SetPlacement(context.Background(), "test", "ten_acme", user, manager, unit)
}

func (h *harness) mustPlace(user, manager, unit string) {
	h.t.Helper()
	if err := h.place(user, manager, unit); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) unit(name, parent string) string {
	h.t.Helper()
	u, err := h.dir.CreateUnit(context.Background(), "test", "ten_acme", name, directory.UnitDepartment, parent)
	if err != nil {
		h.t.Fatal(err)
	}
	return u.ID
}

func ids(body map[string]any) []string {
	out := []string{}
	for _, id := range body["user_ids"].([]any) {
		out = append(out, id.(string))
	}
	return out
}

func sameIDs(got []string, want ...string) bool {
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

func TestReportsDirectAndTransitive(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ceo", "vice", "rep", "other")
	h.mustPlace(u["vice"], u["ceo"], "")
	h.mustPlace(u["rep"], u["vice"], "")
	service := h.serviceToken(otherService)

	status, body := h.do("GET", "/v1/org/members/"+u["ceo"]+"/reports?tenant=ten_acme", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if !sameIDs(ids(body), u["vice"]) {
		t.Errorf("direct: %v", body)
	}
	status, body = h.do("GET", "/v1/org/members/"+u["ceo"]+"/reports?tenant=ten_acme&transitive=true", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if !sameIDs(ids(body), u["vice"], u["rep"]) {
		t.Errorf("transitive: %v", body)
	}
	status, body = h.do("GET", "/v1/org/members/"+u["other"]+"/reports?tenant=ten_acme", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["user_ids"] == nil || len(ids(body)) != 0 {
		t.Errorf("no reports must be an empty list, not null: %v", body)
	}
}

func TestReportsLookThroughSomeoneWhoLeft(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ceo", "vice", "rep")
	h.mustPlace(u["vice"], u["ceo"], "")
	h.mustPlace(u["rep"], u["vice"], "")
	inactive := directory.MemberInactive
	if _, err := h.dir.UpdateMember(context.Background(), "test", "ten_acme", u["vice"], directory.MemberUpdate{Status: &inactive}); err != nil {
		t.Fatal(err)
	}
	status, body := h.do("GET", "/v1/org/members/"+u["ceo"]+"/reports?tenant=ten_acme&transitive=true", h.serviceToken(otherService), nil)
	h.wantStatus(status, body, http.StatusOK)
	if !sameIDs(ids(body), u["rep"]) {
		t.Errorf("reports: %v", body)
	}
}

func TestOrgReadsNeedAServiceTokenAndATenant(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ada")
	token := h.login("ada", "")
	path := "/v1/org/members/" + u["ada"] + "?tenant=ten_acme"
	for name, bearer := range map[string]string{"user": token, "none": ""} {
		if status, _ := h.do("GET", path, bearer, nil); status != http.StatusUnauthorized {
			t.Errorf("%s token: %d", name, status)
		}
	}
	service := h.serviceToken(otherService)
	status, body := h.do("GET", "/v1/org/members/"+u["ada"], service, nil)
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = h.do("GET", "/v1/org/units", service, nil)
	h.wantStatus(status, body, http.StatusBadRequest)
	status, body = h.do("GET", path, service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if body["user_id"] != u["ada"] {
		t.Errorf("member: %v", body)
	}
}

func TestOrgReadsStayInTheNamedTenant(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ada", "boss")
	h.tenant("ten_other")
	h.mustPlace(u["ada"], u["boss"], "")
	unit := h.unit("Sales", "")
	service := h.serviceToken(otherService)
	for _, path := range []string{
		"/v1/org/members/" + u["ada"] + "?tenant=ten_other",
		"/v1/org/members/" + u["boss"] + "/reports?tenant=ten_other",
		"/v1/org/units/" + unit + "/members?tenant=ten_other",
	} {
		if status, body := h.do("GET", path, service, nil); status != http.StatusNotFound {
			t.Errorf("%s: %d %v", path, status, body)
		}
	}
	status, body := h.do("GET", "/v1/org/units?tenant=ten_other", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if units, _ := body["units"].([]any); len(units) != 0 {
		t.Errorf("another tenant's units: %v", body)
	}
}

func TestManagerCycleIsRefused(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("aaa", "bbb", "ccc")
	if err := h.place(u["aaa"], u["aaa"], ""); !errors.Is(err, directory.ErrCycle) {
		t.Errorf("own manager: %v", err)
	}
	h.mustPlace(u["bbb"], u["aaa"], "")
	h.mustPlace(u["ccc"], u["bbb"], "")
	if err := h.place(u["aaa"], u["ccc"], ""); !errors.Is(err, directory.ErrCycle) {
		t.Errorf("a loop of three: %v", err)
	}
	// Moving inside the same line isn't a loop.
	h.mustPlace(u["ccc"], u["aaa"], "")
}

func TestConcurrentEditsCannotBuildACycleTogether(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("aaa", "bbb")
	for round := range 20 {
		h.mustPlace(u["aaa"], "", "")
		h.mustPlace(u["bbb"], "", "")
		var wg sync.WaitGroup
		for _, pair := range [][2]string{{"aaa", "bbb"}, {"bbb", "aaa"}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = h.place(u[pair[0]], u[pair[1]], "")
			}()
		}
		wg.Wait()
		var managed int
		err := h.pool.QueryRow(context.Background(),
			"SELECT count(*) FROM auth.memberships WHERE tenant_id = 'ten_acme' AND manager_id IS NOT NULL").Scan(&managed)
		if err != nil {
			t.Fatal(err)
		}
		if managed != 1 {
			t.Fatalf("round %d: %d managers set, which is a cycle", round, managed)
		}
	}
}

func TestManagerMustBeAnActiveMemberHere(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ada", "gone")
	h.tenant("ten_other")
	stranger := h.user("stranger", map[string]string{"ten_other": directory.RoleMember})
	if err := h.place(u["ada"], stranger, ""); !errors.Is(err, directory.ErrInvalid) {
		t.Errorf("a manager from another tenant: %v", err)
	}
	inactive := directory.MemberInactive
	if _, err := h.dir.UpdateMember(context.Background(), "test", "ten_acme", u["gone"], directory.MemberUpdate{Status: &inactive}); err != nil {
		t.Fatal(err)
	}
	if err := h.place(u["ada"], u["gone"], ""); !errors.Is(err, directory.ErrInvalid) {
		t.Errorf("an inactive manager: %v", err)
	}
	if err := h.place(stranger, "", ""); !errors.Is(err, directory.ErrNotFound) {
		t.Errorf("placing a stranger: %v", err)
	}
}

func TestUnitsStayInsideOneTenant(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	u := h.orgUsers("ada")
	h.tenant("ten_other")
	foreign, err := h.dir.CreateUnit(ctx, "test", "ten_other", "Theirs", directory.UnitTeam, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.place(u["ada"], "", foreign.ID); !errors.Is(err, directory.ErrNotFound) {
		t.Errorf("a unit from another tenant: %v", err)
	}
	if _, err := h.dir.CreateUnit(ctx, "test", "ten_acme", "Ours", directory.UnitTeam, foreign.ID); !errors.Is(err, directory.ErrNotFound) {
		t.Errorf("a parent from another tenant: %v", err)
	}
	mine := h.unit("Mine", "")
	if err := h.dir.UpdateUnit(ctx, "test", "ten_acme", mine, "Mine", directory.UnitTeam, foreign.ID); !errors.Is(err, directory.ErrNotFound) {
		t.Errorf("moving under another tenant: %v", err)
	}
	if err := h.dir.UpdateUnit(ctx, "test", "ten_other", mine, "Taken", directory.UnitTeam, ""); !errors.Is(err, directory.ErrNotFound) {
		t.Errorf("editing another tenant's unit: %v", err)
	}
	if err := h.dir.DeleteUnit(ctx, "test", "ten_other", mine); !errors.Is(err, directory.ErrNotFound) {
		t.Errorf("deleting another tenant's unit: %v", err)
	}
	var mixed string
	err = h.pool.QueryRow(ctx, "INSERT INTO auth.org_units (id, tenant_id, parent_id, name) VALUES ('org_x', 'ten_acme', $1, 'x') RETURNING id", foreign.ID).Scan(&mixed)
	if err == nil {
		t.Error("the database let a unit hang under another tenant")
	}
}

func TestUnitTree(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	u := h.orgUsers("ada", "grace")
	sales := h.unit("Sales", "")
	east := h.unit("East", sales)
	h.mustPlace(u["ada"], "", sales)
	h.mustPlace(u["grace"], "", east)

	units, err := h.dir.ListUnits(ctx, "ten_acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(units) != 2 || units[0].ID != sales || units[1].ID != east || units[1].Depth != 1 || units[0].Members != 1 {
		t.Fatalf("tree: %+v", units)
	}

	service := h.serviceToken(otherService)
	status, body := h.do("GET", "/v1/org/units/"+sales+"/members?tenant=ten_acme", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if !sameIDs(ids(body), u["ada"]) {
		t.Errorf("direct: %v", body)
	}
	status, body = h.do("GET", "/v1/org/units/"+sales+"/members?tenant=ten_acme&transitive=true", service, nil)
	h.wantStatus(status, body, http.StatusOK)
	if !sameIDs(ids(body), u["ada"], u["grace"]) {
		t.Errorf("transitive: %v", body)
	}

	if err := h.dir.UpdateUnit(ctx, "test", "ten_acme", sales, "Sales", directory.UnitDepartment, east); !errors.Is(err, directory.ErrCycle) {
		t.Errorf("a unit under its own child: %v", err)
	}
	if err := h.dir.UpdateUnit(ctx, "test", "ten_acme", sales, "Sales", directory.UnitDepartment, sales); !errors.Is(err, directory.ErrCycle) {
		t.Errorf("a unit under itself: %v", err)
	}
	if err := h.dir.DeleteUnit(ctx, "test", "ten_acme", sales); !errors.Is(err, directory.ErrUnitInUse) {
		t.Errorf("deleting a parent: %v", err)
	}
	if err := h.dir.DeleteUnit(ctx, "test", "ten_acme", east); !errors.Is(err, directory.ErrUnitInUse) {
		t.Errorf("deleting a unit with members: %v", err)
	}
	h.mustPlace(u["grace"], "", "")
	if err := h.dir.DeleteUnit(ctx, "test", "ten_acme", east); err != nil {
		t.Errorf("deleting an empty unit: %v", err)
	}
	if _, err := h.dir.CreateUnit(ctx, "test", "ten_acme", "  ", directory.UnitTeam, ""); !errors.Is(err, directory.ErrInvalid) {
		t.Errorf("a blank name: %v", err)
	}
	if _, err := h.dir.CreateUnit(ctx, "test", "ten_acme", "Fine", "guild", ""); !errors.Is(err, directory.ErrInvalid) {
		t.Errorf("an unknown kind: %v", err)
	}
	if _, err := h.dir.CreateUnit(ctx, "test", "ten_acme", strings.Repeat("é", 101), directory.UnitTeam, ""); !errors.Is(err, directory.ErrInvalid) {
		t.Errorf("a long name: %v", err)
	}
}

func TestOrgChangesAreAudited(t *testing.T) {
	h := newHarness(t, true)
	u := h.orgUsers("ada", "boss")
	unit := h.unit("Sales", "")
	h.mustPlace(u["ada"], u["boss"], unit)
	if h.auditCount("org_unit.create", "success") != 1 || h.auditCount("membership.placement", "success") != 1 {
		t.Error("an org change wrote no audit row")
	}
}

func (h *harness) userID(name string) string {
	h.t.Helper()
	var id string
	err := h.pool.QueryRow(context.Background(), "SELECT user_id FROM auth.user_identifiers WHERE value = $1", name).Scan(&id)
	if err != nil {
		h.t.Fatal(fmt.Errorf("user %s: %w", name, err))
	}
	return id
}
