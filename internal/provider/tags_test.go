// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"reflect"
	"strings"
	"testing"
)

func TestDefinedTagsToOCI(t *testing.T) {
	got, err := definedTagsToOCI(map[string]string{"FinOps.stack": "networking", "FinOps.region": "madrid", "Ops.owner": "dba"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]map[string]interface{}{
		"FinOps": {"stack": "networking", "region": "madrid"},
		"Ops":    {"owner": "dba"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	for _, bad := range []string{"stack", "FinOps.", ".stack", "a.b.c", "Fin Ops.stack"} {
		if _, err := definedTagsToOCI(map[string]string{bad: "x"}); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestDefinedTagsFromOCIIgnores(t *testing.T) {
	live := map[string]map[string]interface{}{
		"FinOps":      {"stack": "networking"},
		"Oracle-Tags": {"CreatedBy": "someone", "CreatedOn": "2026-10-18T10:00:00.000Z"},
	}
	ignore := map[string]bool{"Oracle-Tags.CreatedBy": true, "Oracle-Tags.CreatedOn": true}

	if got, want := definedTagsFromOCI(live, ignore), map[string]string{"FinOps.stack": "networking"}; !reflect.DeepEqual(got, want) {
		t.Errorf("with ignore: got %v, want %v", got, want)
	}
	if got := definedTagsFromOCI(live, nil); len(got) != 3 {
		t.Errorf("without ignore: got %v, want the 3 tags", got)
	}
}

func TestKeepIgnoredDefinedTags(t *testing.T) {
	live := map[string]map[string]interface{}{
		"FinOps":      {"stack": "old", "removed": "x"},
		"Oracle-Tags": {"CreatedBy": "someone"},
	}
	ignore := map[string]bool{"Oracle-Tags.CreatedBy": true}

	// The update sends the configured tags plus the ignored live ones: FinOps.removed goes away.
	got := keepIgnoredDefinedTags(map[string]string{"FinOps.stack": "new"}, live, ignore)
	want := map[string]string{"FinOps.stack": "new", "Oracle-Tags.CreatedBy": "someone"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestCheckRegion(t *testing.T) {
	d := &providerData{region: "eu-madrid-1"}
	ok := []string{
		"ocid1.vcn.oc1.eu-madrid-1.amaaaaaa",
		"ocid1.networksecuritygroup.oc1.eu-madrid-1.aaaa",
		"ocid1.compartment.oc1..aaaa", // no region: nothing to check
		"not-an-ocid",
	}
	for _, id := range ok {
		if err := d.checkRegion("vcn_id", id); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}

	err := d.checkRegion("vcn_id", "ocid1.vcn.oc1.eu-madrid-3.amaaaaaa")
	if err == nil || !strings.Contains(err.Error(), "is in region eu-madrid-3, but this provider configuration uses eu-madrid-1") {
		t.Errorf("other region: got %v", err)
	}

	// Short region codes in older OCIDs.
	if err := (&providerData{region: "us-ashburn-1"}).checkRegion("vcn_id", "ocid1.vcn.oc1.iad.aaaa"); err != nil {
		t.Errorf("short code: %v", err)
	}
	if err := (&providerData{}).checkRegion("vcn_id", "ocid1.vcn.oc1.eu-madrid-3.aaaa"); err != nil {
		t.Errorf("unknown provider region: %v", err)
	}
}
