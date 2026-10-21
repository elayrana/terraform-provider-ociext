// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

// testAccNSGConfig is one ociext_nsg named "test". rules is an HCL list, extra goes inside the block.
func testAccNSGConfig(name, rules, extra string) string {
	return testAccConfig(fmt.Sprintf(`
resource "ociext_nsg" "test" {
  compartment_id = local.compartment_id
  vcn_id         = local.vcn_id
  display_name   = %q
  rules          = %s
  %s
}
`, name, rules, extra))
}

func TestAccNSG_basic(t *testing.T) {
	name := testAccName(t)
	var id string
	ruleIDs := map[string]bool{}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: testAccNSGConfig(name, `[
    { direction = "INGRESS", protocol = "tcp", source = "0.0.0.0/0", ports = "443", description = "HTTPS" },
    { direction = "INGRESS", protocol = "udp", source = "10.0.0.0/16", ports = "53" },
    { direction = "INGRESS", protocol = "icmp", source = "0.0.0.0/0", icmp_type = 3, icmp_code = 4 },
    { direction = "EGRESS", protocol = "all", destination = "0.0.0.0/0" },
  ]`, `freeform_tags = { env = "acc" }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.test", &id),
					resource.TestCheckResourceAttr("ociext_nsg.test", "display_name", name),
					resource.TestCheckResourceAttr("ociext_nsg.test", "freeform_tags.env", "acc"),
					resource.TestCheckResourceAttr("ociext_nsg.test", "rules.#", "4"),
					resource.TestCheckTypeSetElemNestedAttrs("ociext_nsg.test", "rules.*", map[string]string{
						"protocol": "tcp", "source": "0.0.0.0/0", "ports": "443", "description": "HTTPS", "stateless": "false",
					}),
					testAccCheckLiveRules(t, &id, 4, 0),
					testAccCaptureRuleIDs(t, &id, ruleIDs),
				),
			},
			{
				// Remove the UDP rule, add an SSH rule, change a description, rename and remove the tags.
				Config: testAccNSGConfig(name+"-renamed", `[
    { direction = "INGRESS", protocol = "tcp", source = "0.0.0.0/0", ports = "443", description = "Public HTTPS" },
    { direction = "INGRESS", protocol = "tcp", source = "10.0.5.0/24", ports = "22" },
    { direction = "INGRESS", protocol = "icmp", source = "0.0.0.0/0", icmp_type = 3, icmp_code = 4 },
    { direction = "EGRESS", protocol = "all", destination = "0.0.0.0/0" },
  ]`, `freeform_tags = {}`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ociext_nsg.test", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ociext_nsg.test", "display_name", name+"-renamed"),
					resource.TestCheckNoResourceAttr("ociext_nsg.test", "freeform_tags.env"),
					resource.TestCheckResourceAttr("ociext_nsg.test", "rules.#", "4"),
					testAccCheckLiveRules(t, &id, 4, 0),
					// HTTPS (updated in place), ICMP and egress keep their OCI rule.
					testAccCheckRulesKept(t, &id, ruleIDs, 3),
				),
			},
			{
				// Remove the description: the rule is updated in place and OCI clears it.
				Config: testAccNSGConfig(name+"-renamed", `[
    { direction = "INGRESS", protocol = "tcp", source = "0.0.0.0/0", ports = "443" },
    { direction = "INGRESS", protocol = "tcp", source = "10.0.5.0/24", ports = "22" },
    { direction = "INGRESS", protocol = "icmp", source = "0.0.0.0/0", icmp_type = 3, icmp_code = 4 },
    { direction = "EGRESS", protocol = "all", destination = "0.0.0.0/0" },
  ]`, `freeform_tags = {}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckTypeSetElemNestedAttrs("ociext_nsg.test", "rules.*", map[string]string{
						"protocol": "tcp", "source": "0.0.0.0/0", "ports": "443",
					}),
					testAccCheckRulesKept(t, &id, ruleIDs, 3),
					testAccCheckNoDescriptions(t, &id),
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

// TestAccNSG_drift changes the NSG outside Terraform: the plan shows it and the apply fixes it,
// without touching the rules that point to an NSG.
func TestAccNSG_drift(t *testing.T) {
	name := testAccName(t)
	var id string
	rules := `[
    { direction = "INGRESS", protocol = "tcp", source = "0.0.0.0/0", ports = "443" },
    { direction = "INGRESS", protocol = "udp", source = "10.0.0.0/16", ports = "53" },
    { direction = "EGRESS", protocol = "all", destination = "0.0.0.0/0" },
  ]`

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: testAccNSGConfig(name, rules, ""),
				Check:  testAccCaptureID("ociext_nsg.test", &id),
			},
			{
				PreConfig: func() {
					extra := ingress("tcp", "172.16.0.0/12")
					extra.Ports = types.StringValue("8080")
					testAccAddRules(t, id, extra, ingress("all", id))
					udp := ingress("udp", "10.0.0.0/16")
					udp.Ports = types.StringValue("53")
					testAccRemoveRules(t, id, udp)
				},
				Config: testAccNSGConfig(name, rules, ""),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ociext_nsg.test", plancheck.ResourceActionUpdate),
					},
				},
				// The manual CIDR rule is gone and the UDP rule is back; the manual NSG rule stays.
				Check: testAccCheckLiveRules(t, &id, 3, 1),
			},
		},
	})
}

// TestAccNSG_deletedOutside deletes the NSG outside Terraform: the next plan creates it again.
func TestAccNSG_deletedOutside(t *testing.T) {
	name := testAccName(t)
	var id string
	config := testAccNSGConfig(name, `[
    { direction = "EGRESS", protocol = "all", destination = "0.0.0.0/0" },
  ]`, "")

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  testAccCaptureID("ociext_nsg.test", &id),
			},
			{
				PreConfig: func() { testAccDeleteNSG(t, id) },
				Config:    config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ociext_nsg.test", plancheck.ResourceActionCreate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.test", &id),
					testAccCheckLiveRules(t, &id, 1, 0),
				),
			},
		},
	})
}

// TestAccNSG_manyRules goes through the batches of 25 rules and the rules-per-NSG limit.
func TestAccNSG_manyRules(t *testing.T) {
	name := testAccName(t)
	var id string
	ruleIDs := map[string]bool{}
	portRules := func(from, to int) string {
		return fmt.Sprintf(`[for p in range(%d, %d) : { direction = "INGRESS", protocol = "tcp", source = "10.0.0.0/16", ports = tostring(p) }]`, from, to)
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: testAccNSGConfig(name, portRules(10000, 10110), ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.test", &id),
					resource.TestCheckResourceAttr("ociext_nsg.test", "rules.#", "110"),
					testAccCheckLiveRules(t, &id, 110, 0),
					testAccCaptureRuleIDs(t, &id, ruleIDs),
				),
			},
			{
				// 30 rules out, 30 in, 80 untouched.
				Config: testAccNSGConfig(name, portRules(10030, 10140), ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ociext_nsg.test", "rules.#", "110"),
					testAccCheckLiveRules(t, &id, 110, 0),
					testAccCheckRulesKept(t, &id, ruleIDs, 80),
				),
			},
			{
				Config:      testAccNSGConfig(name, portRules(10000, 10121), ""),
				ExpectError: errorText("The NSG has 121 rules and the limit is 120"),
			},
		},
	})
}

// TestAccNSG_protocols applies one rule of each kind and checks that switching a protocol
// between its number and its name does not recreate any rule.
func TestAccNSG_protocols(t *testing.T) {
	name := testAccName(t)
	var id string
	ruleIDs := map[string]bool{}
	rules := func(gre, sctp string) string {
		return fmt.Sprintf(`[
    { direction = "INGRESS", protocol = "tcp", source = "10.0.0.0/16", ports = "8000-8100", source_ports = "1024-65535" },
    { direction = "EGRESS", protocol = "tcp", destination = "0.0.0.0/0", ports = "443" },
    { direction = "INGRESS", protocol = "udp", source = "10.0.0.0/16", source_ports = "123" },
    { direction = "EGRESS", protocol = "udp", destination = "0.0.0.0/0", ports = "123" },
    { direction = "INGRESS", protocol = "icmp", source = "0.0.0.0/0", icmp_type = 3, icmp_code = 4 },
    { direction = "INGRESS", protocol = "icmp", source = "10.0.0.0/8", icmp_type = 8 },
    { direction = "INGRESS", protocol = "icmp", source = "10.1.0.0/16" },
    { direction = "INGRESS", protocol = "ipip", source = "10.0.0.0/8" },
    { direction = "INGRESS", protocol = %q, source = "10.0.0.0/8" },
    { direction = "INGRESS", protocol = "esp", source = "10.0.0.0/8" },
    { direction = "INGRESS", protocol = "ah", source = "10.0.0.0/8" },
    { direction = "INGRESS", protocol = %q, source = "10.0.0.0/8" },
    { direction = "INGRESS", protocol = "vrrp", source = "10.0.0.0/8" },
    { direction = "INGRESS", protocol = "99", source = "10.0.0.0/8" },
    { direction = "INGRESS", protocol = "all", source = "10.2.0.0/16", stateless = true },
  ]`, gre, sctp)
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{
				Config: testAccNSGConfig(name, rules("gre", "sctp"), ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCaptureID("ociext_nsg.test", &id),
					resource.TestCheckResourceAttr("ociext_nsg.test", "rules.#", "15"),
					testAccCheckLiveRules(t, &id, 15, 0),
					testAccCaptureRuleIDs(t, &id, ruleIDs),
				),
			},
			{
				ResourceName:      "ociext_nsg.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				Config: testAccNSGConfig(name, rules("47", "132"), ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckTypeSetElemNestedAttrs("ociext_nsg.test", "rules.*", map[string]string{"protocol": "47"}),
					testAccCheckRulesKept(t, &id, ruleIDs, 15),
				),
			},
		},
	})
}

// TestAccNSG_invalid checks the errors raised at plan time, before anything is created.
func TestAccNSG_invalid(t *testing.T) {
	name := testAccName(t)
	step := func(rules, want string) resource.TestStep {
		return resource.TestStep{
			Config:      testAccNSGConfig(name, rules, ""),
			PlanOnly:    true,
			ExpectError: errorText(want),
		}
	}

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			step(`[{ direction = "INGRESS", protocol = "0", source = "10.0.0.0/8" }]`,
				`must be all, a protocol name`),
			step(`[{ direction = "INGRESS", protocol = "icmp", source = "10.0.0.0/8", ports = "80" }]`,
				`ports and source_ports are only allowed with tcp or udp`),
			step(`[{ direction = "INGRESS", protocol = "tcp", source = "10.0.0.0/8", icmp_type = 3 }]`,
				`icmp_type and icmp_code are only allowed with icmp or icmpv6`),
			step(`[{ direction = "INGRESS", protocol = "icmp", source = "10.0.0.0/8", icmp_code = 4 }]`,
				`icmp_code needs icmp_type`),
			step(`[{ direction = "INGRESS", protocol = "all", source = "ocid1.networksecuritygroup.oc1.eu-madrid-1.aaaa" }]`,
				`points to an NSG: those rules go in ociext_nsg_peer_rules`),
			step(`[
    { direction = "INGRESS", protocol = "tcp", source = "10.0.0.0/8", ports = "443" },
    { direction = "INGRESS", protocol = "6", source = "10.0.0.0/8", ports = "443-443", description = "same" },
  ]`, `More than one rule matches the same traffic`),
		},
	})
}

// TestAccNSG_peerRuleRejected points a rule of ociext_nsg to an NSG that already exists:
// the error comes at apply time, before the new NSG is created.
func TestAccNSG_peerRuleRejected(t *testing.T) {
	name := testAccName(t)
	base := fmt.Sprintf(`
resource "ociext_nsg" "a" {
  compartment_id = local.compartment_id
  vcn_id         = local.vcn_id
  display_name   = "%s-a"
}
`, name)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckNSGsDestroyed(t),
		Steps: []resource.TestStep{
			{Config: testAccConfig(base)},
			{
				Config: testAccConfig(base + fmt.Sprintf(`
resource "ociext_nsg" "b" {
  compartment_id = local.compartment_id
  vcn_id         = local.vcn_id
  display_name   = "%s-b"
  rules          = [{ direction = "INGRESS", protocol = "all", source = ociext_nsg.a.id }]
}
`, name)),
				ExpectError: errorText("points to an NSG: those rules go in ociext_nsg_peer_rules"),
			},
			{
				// ociext_nsg.b was not created, so with b gone from the config there is nothing to do.
				Config:   testAccConfig(base),
				PlanOnly: true,
			},
		},
	})
}
