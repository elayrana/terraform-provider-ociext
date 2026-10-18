// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// The test tenancy has tag defaults for Oracle-Tags.CreatedBy and CreatedOn, as new
// tenancies do: every NSG gets them, so they exercise ignore_defined_tags.
const testAccIgnoreOracleTags = `  ignore_defined_tags = ["Oracle-Tags.CreatedBy", "Oracle-Tags.CreatedOn"]` + "\n"

func testAccTagsConfig(name, tags string) string {
	return testAccConfigProvider(testAccIgnoreOracleTags, fmt.Sprintf(`
resource "ociext_nsg" "test" {
  compartment_id = local.compartment_id
  vcn_id         = local.vcn_id
  display_name   = %q
  %s
}
`, name, tags))
}

// testAccCheckLiveNSG runs check on the NSG as OCI returns it.
func testAccCheckLiveNSG(t *testing.T, id *string, check func(core.NetworkSecurityGroup) error) func(*terraform.State) error {
	return func(*terraform.State) error {
		got, err := testAccData(t).network.GetNetworkSecurityGroup(context.Background(), core.GetNetworkSecurityGroupRequest{
			NetworkSecurityGroupId: common.String(*id),
		})
		if err != nil {
			return err
		}
		return check(got.NetworkSecurityGroup)
	}
}

func hasOracleTags(n core.NetworkSecurityGroup) error {
	if _, ok := n.DefinedTags["Oracle-Tags"]["CreatedBy"]; !ok {
		return fmt.Errorf("the NSG lost its Oracle-Tags.CreatedBy tag: %v", n.DefinedTags)
	}
	return nil
}

func TestAccNSG_freeformTags(t *testing.T) {
	name := testAccName(t)
	var id string

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				// defined_tags = {}: no defined tags of ours, and the ignored Oracle-Tags cause no drift.
				Config: testAccTagsConfig(name, `freeform_tags = { team = "dba", env = "acc" }
  defined_tags = {}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.test", &id),
					resource.TestCheckResourceAttr("ociext_nsg.test", "freeform_tags.%", "2"),
					resource.TestCheckResourceAttr("ociext_nsg.test", "freeform_tags.team", "dba"),
					resource.TestCheckResourceAttr("ociext_nsg.test", "defined_tags.%", "0"),
					testAccCheckLiveNSG(t, &id, hasOracleTags),
				),
			},
			{
				// Without the attribute, the tags are not managed: nothing changes and the state keeps them.
				Config: testAccTagsConfig(name, `defined_tags = {}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				Check: resource.TestCheckResourceAttr("ociext_nsg.test", "freeform_tags.team", "dba"),
			},
			{
				ResourceName:      "ociext_nsg.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// {} removes them all, and the update keeps the ignored defined tags.
				Config: testAccTagsConfig(name, `freeform_tags = {}
  defined_tags = {}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ociext_nsg.test", "freeform_tags.%", "0"),
					testAccCheckLiveNSG(t, &id, func(n core.NetworkSecurityGroup) error {
						if len(n.FreeformTags) != 0 {
							return fmt.Errorf("freeform tags left in OCI: %v", n.FreeformTags)
						}
						return hasOracleTags(n)
					}),
				),
			},
		},
	})
}

// TestAccNSG_definedTags needs a defined tag the tests may set, e.g. OCIEXT_TEST_DEFINED_TAG=ociext-test.env.
func TestAccNSG_definedTags(t *testing.T) {
	tag := os.Getenv(envTestDefinedTag)
	if tag == "" {
		t.Skipf("%s is not set", envTestDefinedTag)
	}
	name := testAccName(t)
	var id string
	tags := func(v string) string { return fmt.Sprintf(`defined_tags = { %q = %q }`, tag, v) }

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: testAccTagsConfig(name, tags("one")),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.test", &id),
					resource.TestCheckResourceAttr("ociext_nsg.test", "defined_tags.%", "1"),
					resource.TestCheckResourceAttr("ociext_nsg.test", "defined_tags."+tag, "one"),
				),
			},
			{
				// The update replaces our tag and keeps the ignored ones.
				Config: testAccTagsConfig(name, tags("two")),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ociext_nsg.test", "defined_tags."+tag, "two"),
					testAccCheckLiveNSG(t, &id, hasOracleTags),
				),
			},
			{
				ResourceName:      "ociext_nsg.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccTagsConfig(name, `defined_tags = {}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ociext_nsg.test", "defined_tags.%", "0"),
					testAccCheckLiveNSG(t, &id, hasOracleTags),
				),
			},
		},
	})
}

// TestAccNSG_unmanagedTags leaves the tags to OCI and ignores nothing: the state shows the
// Oracle-Tags that the tag defaults set, and there is no drift.
func TestAccNSG_unmanagedTags(t *testing.T) {
	name := testAccName(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: testAccNSGConfig(name, "null", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ociext_nsg.test", "defined_tags.Oracle-Tags.CreatedBy"),
					resource.TestCheckResourceAttr("ociext_nsg.test", "freeform_tags.%", "0"),
				),
			},
			{
				ResourceName:      "ociext_nsg.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccNSG_otherRegion creates an NSG in a VCN of another region: the error says so
// before any call to OCI.
func TestAccNSG_otherRegion(t *testing.T) {
	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfig(`
resource "ociext_nsg" "test" {
  compartment_id = local.compartment_id
  vcn_id         = "ocid1.vcn.oc1.ap-tokyo-1.amaaaaaaociexttestnotarealvcn"
}
`),
				ExpectError: errorText("is in region ap-tokyo-1, but this provider configuration uses"),
			},
		},
	})
}
