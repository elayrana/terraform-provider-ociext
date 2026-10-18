// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

// testAccPeerNSGs is two NSGs, app and db, with one CIDR rule each.
func testAccPeerNSGs(name string) string {
	return fmt.Sprintf(`
resource "ociext_nsg" "app" {
  compartment_id = local.compartment_id
  vcn_id         = local.vcn_id
  display_name   = "%[1]s-app"
  rules          = [{ direction = "INGRESS", protocol = "tcp", source = "0.0.0.0/0", ports = "443" }]
}

resource "ociext_nsg" "db" {
  compartment_id = local.compartment_id
  vcn_id         = local.vcn_id
  display_name   = "%[1]s-db"
  rules          = [{ direction = "EGRESS", protocol = "all", destination = "0.0.0.0/0" }]
}
`, name)
}

// testAccPeerRules is app and db referencing each other, and app referencing itself.
func testAccPeerRules(name, extraAppRules string) string {
	return testAccConfig(testAccPeerNSGs(name) + fmt.Sprintf(`
resource "ociext_nsg_peer_rules" "app" {
  nsg_id = ociext_nsg.app.id
  rules = [
    { direction = "INGRESS", protocol = "all", source = ociext_nsg.app.id },
    { direction = "EGRESS", protocol = "tcp", destination = ociext_nsg.db.id, ports = "5432" },
    %s
  ]
}

resource "ociext_nsg_peer_rules" "db" {
  nsg_id = ociext_nsg.db.id
  rules  = [{ direction = "INGRESS", protocol = "tcp", source = ociext_nsg.app.id, ports = "5432" }]
}
`, extraAppRules))
}

func TestAccNSGPeerRules_basic(t *testing.T) {
	name := testAccName(t)
	var appID, dbID string
	ruleIDs := map[string]bool{}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				// No dependency cycle, although app and db reference each other.
				Config: testAccPeerRules(name, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.app", &appID),
					testAccCaptureID("ociext_nsg.db", &dbID),
					resource.TestCheckResourceAttrPair("ociext_nsg_peer_rules.app", "id", "ociext_nsg.app", "id"),
					resource.TestCheckResourceAttrPair("ociext_nsg_peer_rules.app", "nsg_id", "ociext_nsg.app", "id"),
					resource.TestCheckResourceAttr("ociext_nsg_peer_rules.app", "rules.#", "2"),
					resource.TestCheckResourceAttr("ociext_nsg.app", "rules.#", "1"),
					testAccCheckLiveRules(t, &appID, 1, 2),
					testAccCheckLiveRules(t, &dbID, 1, 1),
					testAccCaptureRuleIDs(t, &appID, ruleIDs),
				),
			},
			{
				// One peer rule more on app: nothing else changes in OCI.
				Config: testAccPeerRules(name, `{ direction = "EGRESS", protocol = "udp", destination = ociext_nsg.db.id, ports = "5000-5010" },`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ociext_nsg_peer_rules.app", plancheck.ResourceActionUpdate),
						plancheck.ExpectResourceAction("ociext_nsg.app", plancheck.ResourceActionNoop),
						plancheck.ExpectResourceAction("ociext_nsg_peer_rules.db", plancheck.ResourceActionNoop),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ociext_nsg_peer_rules.app", "rules.#", "3"),
					testAccCheckLiveRules(t, &appID, 1, 3),
					testAccCheckRulesKept(t, &appID, ruleIDs, 3),
				),
			},
			{
				ResourceName:      "ociext_nsg_peer_rules.app",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "ociext_nsg.app",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccNSGPeerRules_drift changes rules of both kinds outside Terraform: each resource
// fixes only its own kind.
func TestAccNSGPeerRules_drift(t *testing.T) {
	name := testAccName(t)
	var appID, dbID string

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: testAccPeerRules(name, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.app", &appID),
					testAccCaptureID("ociext_nsg.db", &dbID),
				),
			},
			{
				PreConfig: func() {
					peer := ingress("tcp", dbID)
					peer.Ports = types.StringValue("9000")
					cidr := ingress("tcp", "172.16.0.0/12")
					cidr.Ports = types.StringValue("8080")
					testAccAddRules(t, appID, peer, cidr)

					managed := ingress("tcp", appID)
					managed.Ports = types.StringValue("5432")
					testAccRemoveRules(t, dbID, managed)
				},
				Config: testAccPeerRules(name, ""),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ociext_nsg.app", plancheck.ResourceActionUpdate),
						plancheck.ExpectResourceAction("ociext_nsg_peer_rules.app", plancheck.ResourceActionUpdate),
						plancheck.ExpectResourceAction("ociext_nsg_peer_rules.db", plancheck.ResourceActionUpdate),
						plancheck.ExpectResourceAction("ociext_nsg.db", plancheck.ResourceActionNoop),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckLiveRules(t, &appID, 1, 2),
					testAccCheckLiveRules(t, &dbID, 1, 1),
				),
			},
		},
	})
}

// TestAccNSGPeerRules_guard creates peer rules on an NSG that already has a peer rule
// not in the configuration: Create fails and changes nothing.
func TestAccNSGPeerRules_guard(t *testing.T) {
	name := testAccName(t)
	var appID, dbID string
	peerRules := func(rules string) string {
		return testAccConfig(testAccPeerNSGs(name) + fmt.Sprintf(`
resource "ociext_nsg_peer_rules" "db" {
  nsg_id = ociext_nsg.db.id
  rules  = %s
}
`, rules))
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: testAccConfig(testAccPeerNSGs(name)),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.app", &appID),
					testAccCaptureID("ociext_nsg.db", &dbID),
				),
			},
			{
				PreConfig: func() {
					foreign := ingress("tcp", appID)
					foreign.Ports = types.StringValue("9000")
					testAccAddRules(t, dbID, foreign)
				},
				Config:      peerRules(`[{ direction = "INGRESS", protocol = "tcp", source = ociext_nsg.app.id, ports = "5432" }]`),
				ExpectError: errorText("already has 1 rule(s) of type NSG that are not in this configuration"),
			},
			{
				// Nothing changed: the foreign rule is still the only peer rule.
				Config: testAccConfig(testAccPeerNSGs(name)),
				Check:  testAccCheckLiveRules(t, &dbID, 1, 1),
			},
			{
				// With the foreign rule in the configuration, it is adopted.
				Config: peerRules(`[
    { direction = "INGRESS", protocol = "tcp", source = ociext_nsg.app.id, ports = "5432" },
    { direction = "INGRESS", protocol = "tcp", source = ociext_nsg.app.id, ports = "9000" },
  ]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ociext_nsg_peer_rules.db", "rules.#", "2"),
					testAccCheckLiveRules(t, &dbID, 1, 2),
				),
			},
		},
	})
}

// TestAccNSGPeerRules_destroy removes only the peer rules: the NSG and its CIDR rules stay.
func TestAccNSGPeerRules_destroy(t *testing.T) {
	name := testAccName(t)
	var appID, dbID string

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: testAccPeerRules(name, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.app", &appID),
					testAccCaptureID("ociext_nsg.db", &dbID),
				),
			},
			{
				Config: testAccConfig(testAccPeerNSGs(name)),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckLiveRules(t, &appID, 1, 0),
					testAccCheckLiveRules(t, &dbID, 1, 0),
				),
			},
		},
	})
}

// TestAccNSGPeerRules_cidrRejected puts a CIDR rule in ociext_nsg_peer_rules.
func TestAccNSGPeerRules_cidrRejected(t *testing.T) {
	name := testAccName(t)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccConfig(testAccPeerNSGs(name) + `
resource "ociext_nsg_peer_rules" "app" {
  nsg_id = ociext_nsg.app.id
  rules  = [{ direction = "INGRESS", protocol = "tcp", source = "10.0.0.0/8", ports = "22" }]
}
`),
				PlanOnly:    true,
				ExpectError: errorText("does not point to an NSG: rules with a CIDR block or a service go in the rules of ociext_nsg"),
			},
		},
	})
}
