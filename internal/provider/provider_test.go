// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// Acceptance tests create real NSGs. They run with TF_ACC=1 and these variables;
// without them they are skipped, so CI (which has no OCI credentials) stays green.
// There is no default profile on purpose: a test must never run against a tenancy by accident.
const (
	envTestProfile       = "OCIEXT_TEST_PROFILE"
	envTestCompartmentID = "OCIEXT_TEST_COMPARTMENT_ID"
	envTestVcnID         = "OCIEXT_TEST_VCN_ID"
	envTestRegion        = "OCIEXT_TEST_REGION"      // optional, defaults to the region of the profile
	envTestConfigFile    = "OCIEXT_TEST_CONFIG_FILE" // optional, defaults to ~/.oci/config
)

// testAccNamePrefix starts the display name of every NSG an acceptance test creates.
const testAccNamePrefix = "ociext-acc-"

// testAccProtoV6ProviderFactories is used to instantiate a provider during acceptance testing.
// The factory function is called for each Terraform CLI command to create a provider
// server that the CLI can connect to and interact with.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"ociext": providerserver.NewProtocol6WithError(New("test")()),
}

func testAccPreCheck(t *testing.T) {
	for _, v := range []string{envTestProfile, envTestCompartmentID, envTestVcnID} {
		if os.Getenv(v) == "" {
			t.Skipf("%s, %s and %s must be set to run acceptance tests", envTestProfile, envTestCompartmentID, envTestVcnID)
		}
	}
}

// testAccConfig prepends the provider block and the compartment and VCN locals to a test configuration.
func testAccConfig(body string) string {
	var optional string
	if f := os.Getenv(envTestConfigFile); f != "" {
		optional += fmt.Sprintf("  config_file_path    = %q\n", f)
	}
	if r := os.Getenv(envTestRegion); r != "" {
		optional += fmt.Sprintf("  region              = %q\n", r)
	}
	return fmt.Sprintf(`provider "ociext" {
  config_file_profile = %q
%s}

locals {
  compartment_id = %q
  vcn_id         = %q
}
`, os.Getenv(envTestProfile), optional, os.Getenv(envTestCompartmentID), os.Getenv(envTestVcnID)) + body
}

var (
	testAccDataOnce sync.Once
	testAccDataVal  *providerData
	testAccDataErr  error
)

// testAccData returns an OCI client with the same credentials as the provider under test,
// used to check OCI directly and to make changes outside Terraform.
func testAccData(t *testing.T) *providerData {
	t.Helper()
	testAccDataOnce.Do(func() {
		cp, err := apiKeyConfigProvider(os.Getenv(envTestConfigFile), os.Getenv(envTestProfile))
		if err != nil {
			testAccDataErr = err
			return
		}
		network, err := core.NewVirtualNetworkClientWithConfigurationProvider(cp)
		if err != nil {
			testAccDataErr = err
			return
		}
		if r := os.Getenv(envTestRegion); r != "" {
			network.SetRegion(r)
		}
		retry := common.DefaultRetryPolicy()
		network.Configuration.RetryPolicy = &retry
		testAccDataVal = &providerData{network: network, maxRulesPerNSG: defaultMaxRulesPerNSG}
	})
	if testAccDataErr != nil {
		t.Fatalf("OCI client: %v", testAccDataErr)
	}
	return testAccDataVal
}

// testAccCaptureID stores the id of a resource, so that a later step can change it outside Terraform.
func testAccCaptureID(name string, id *string) func(*terraform.State) error {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("%s not found in state", name)
		}
		*id = rs.Primary.ID
		return nil
	}
}

// testAccCheckLiveRules checks how many rules the NSG has in OCI, split by owner.
func testAccCheckLiveRules(t *testing.T, id *string, wantCIDR, wantPeer int) func(*terraform.State) error {
	return func(*terraform.State) error {
		live, err := testAccData(t).listRules(context.Background(), *id)
		if err != nil {
			return err
		}
		if got := len(inScope(live, false)); got != wantCIDR {
			return fmt.Errorf("NSG %s has %d CIDR and service rules in OCI, want %d", *id, got, wantCIDR)
		}
		if got := len(inScope(live, true)); got != wantPeer {
			return fmt.Errorf("NSG %s has %d NSG rules in OCI, want %d", *id, got, wantPeer)
		}
		return nil
	}
}

// testAccCaptureRuleIDs stores the OCI rule IDs of an NSG.
func testAccCaptureRuleIDs(t *testing.T, id *string, ids map[string]bool) func(*terraform.State) error {
	return func(*terraform.State) error {
		live, err := testAccData(t).listRules(context.Background(), *id)
		if err != nil {
			return err
		}
		clear(ids)
		for _, l := range live {
			ids[l.ID] = true
		}
		return nil
	}
}

// testAccCheckRulesKept checks that exactly want rules captured earlier still exist with the
// same OCI ID: the apply did not delete and recreate them.
func testAccCheckRulesKept(t *testing.T, id *string, before map[string]bool, want int) func(*terraform.State) error {
	return func(*terraform.State) error {
		live, err := testAccData(t).listRules(context.Background(), *id)
		if err != nil {
			return err
		}
		kept := 0
		for _, l := range live {
			if before[l.ID] {
				kept++
			}
		}
		if kept != want {
			return fmt.Errorf("NSG %s kept %d of its previous rules, want %d", *id, kept, want)
		}
		return nil
	}
}

// testAccAddRules adds rules to an NSG outside Terraform.
func testAccAddRules(t *testing.T, id string, rules ...nsgRuleModel) {
	t.Helper()
	var c ruleChanges
	for _, m := range rules {
		c.Add = append(c.Add, mustRule(t, m))
	}
	if diags := testAccData(t).applyRuleChanges(context.Background(), id, c, 0); diags.HasError() {
		t.Fatalf("adding rules by hand: %v", diags)
	}
}

// testAccRemoveRules removes the rules of an NSG that match the given ones, outside Terraform.
func testAccRemoveRules(t *testing.T, id string, rules ...nsgRuleModel) {
	t.Helper()
	d := testAccData(t)
	live, err := d.listRules(context.Background(), id)
	if err != nil {
		t.Fatalf("listing rules: %v", err)
	}
	var c ruleChanges
	for _, m := range rules {
		k := mustRule(t, m).key()
		found := false
		for _, l := range live {
			if l.Rule.key() == k {
				c.Remove = append(c.Remove, l.ID)
				found = true
			}
		}
		if !found {
			t.Fatalf("NSG %s has no rule %s to remove", id, k)
		}
	}
	if diags := d.applyRuleChanges(context.Background(), id, c, 0); diags.HasError() {
		t.Fatalf("removing rules by hand: %v", diags)
	}
}

// testAccDeleteNSG deletes an NSG outside Terraform and waits until it is gone.
func testAccDeleteNSG(t *testing.T, id string) {
	t.Helper()
	ctx := context.Background()
	network := testAccData(t).network
	if _, err := network.DeleteNetworkSecurityGroup(ctx, core.DeleteNetworkSecurityGroupRequest{
		NetworkSecurityGroupId: common.String(id),
	}); err != nil {
		t.Fatalf("deleting NSG by hand: %v", err)
	}
	for deadline := time.Now().Add(nsgWaitTimeout); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		got, err := network.GetNetworkSecurityGroup(ctx, core.GetNetworkSecurityGroupRequest{NetworkSecurityGroupId: common.String(id)})
		if isNotFound(err) || (err == nil && got.LifecycleState == core.NetworkSecurityGroupLifecycleStateTerminated) {
			return
		}
	}
	t.Fatalf("NSG %s was not deleted in time", id)
}

// testAccCheckNSGsDestroyed checks that no NSG of the state is left in OCI.
func testAccCheckNSGsDestroyed(t *testing.T) func(*terraform.State) error {
	return func(s *terraform.State) error {
		for name, rs := range s.RootModule().Resources {
			if rs.Type != "ociext_nsg" {
				continue
			}
			got, err := testAccData(t).network.GetNetworkSecurityGroup(context.Background(), core.GetNetworkSecurityGroupRequest{
				NetworkSecurityGroupId: common.String(rs.Primary.ID),
			})
			if isNotFound(err) || (err == nil && isGone(got.LifecycleState)) {
				continue
			}
			if err != nil {
				return err
			}
			return fmt.Errorf("%s (%s) still exists in state %s", name, rs.Primary.ID, got.LifecycleState)
		}
		return nil
	}
}

// errorText matches an error message however Terraform wraps its lines.
func errorText(text string) *regexp.Regexp {
	return regexp.MustCompile(strings.ReplaceAll(regexp.QuoteMeta(text), " ", `\s+`))
}

// testAccName returns a display name that is unique to one test run.
func testAccName(t *testing.T) string {
	name := strings.ToLower(strings.TrimPrefix(t.Name(), "TestAcc"))
	return fmt.Sprintf("%s%s-%d", testAccNamePrefix, strings.ReplaceAll(name, "_", "-"), time.Now().Unix()%100000)
}
