// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func ingress(protocol, source string) nsgRuleModel {
	m := emptyRuleModel()
	m.Direction = types.StringValue(directionIngress)
	m.Protocol = types.StringValue(protocol)
	m.Source = types.StringValue(source)
	return m
}

func egress(protocol, destination string) nsgRuleModel {
	m := emptyRuleModel()
	m.Direction = types.StringValue(directionEgress)
	m.Protocol = types.StringValue(protocol)
	m.Destination = types.StringValue(destination)
	return m
}

func emptyRuleModel() nsgRuleModel {
	return nsgRuleModel{
		Source:      types.StringNull(),
		Destination: types.StringNull(),
		Ports:       types.StringNull(),
		SourcePorts: types.StringNull(),
		IcmpType:    types.Int64Null(),
		IcmpCode:    types.Int64Null(),
		Description: types.StringNull(),
		Stateless:   types.BoolValue(false),
	}
}

func mustRule(t *testing.T, m nsgRuleModel) nsgRule {
	t.Helper()
	r, err := m.toRule()
	if err != nil {
		t.Fatalf("toRule: %v", err)
	}
	return r
}

func TestRuleKey(t *testing.T) {
	https := ingress("tcp", "0.0.0.0/0")
	https.Ports = types.StringValue("443")

	icmp := ingress("icmp", "10.0.0.0/8")
	icmp.IcmpType = types.Int64Value(3)
	icmp.IcmpCode = types.Int64Value(4)

	ssh := ingress("tcp", "10.0.1.0/24")
	ssh.Ports = types.StringValue("22")
	ssh.SourcePorts = types.StringValue("1024-65535")

	cases := map[string]nsgRuleModel{
		"INGRESS_tcp_0.0.0.0/0_dst:443":                          https,
		"INGRESS_icmp_10.0.0.0/8_icmp:3-4":                       icmp,
		"INGRESS_tcp_10.0.1.0/24_src:1024-65535_dst:22":          ssh,
		"EGRESS_all_0.0.0.0/0":                                   egress("all", "0.0.0.0/0"),
		"EGRESS_all_all-fra-services-in-oracle-services-network": egress("all", "all-fra-services-in-oracle-services-network"),
	}
	for want, m := range cases {
		if got := mustRule(t, m).key(); got != want {
			t.Errorf("key = %q, want %q", got, want)
		}
	}
}

func TestRuleKeyIsNormalized(t *testing.T) {
	a := ingress("tcp", "10.0.1.5/24")
	a.Ports = types.StringValue("443")
	a.Description = types.StringValue("one")

	b := ingress("6", "10.0.1.0/24")
	b.Ports = types.StringValue("443-443")
	b.Description = types.StringValue("other")
	b.Stateless = types.BoolValue(true)

	if ka, kb := mustRule(t, a).key(), mustRule(t, b).key(); ka != kb {
		t.Errorf("keys differ: %q vs %q", ka, kb)
	}
}

func TestRuleValidation(t *testing.T) {
	ingressWithDestination := ingress("tcp", "0.0.0.0/0")
	ingressWithDestination.Destination = types.StringValue("0.0.0.0/0")

	portsOnICMP := ingress("icmp", "0.0.0.0/0")
	portsOnICMP.Ports = types.StringValue("22")

	icmpOnTCP := ingress("tcp", "0.0.0.0/0")
	icmpOnTCP.IcmpType = types.Int64Value(3)

	codeWithoutType := ingress("icmp", "0.0.0.0/0")
	codeWithoutType.IcmpCode = types.Int64Value(4)

	reversedPorts := ingress("tcp", "0.0.0.0/0")
	reversedPorts.Ports = types.StringValue("443-80")

	cases := map[string]nsgRuleModel{
		"ingress with destination": ingressWithDestination,
		"egress with source":       func() nsgRuleModel { m := egress("all", "0.0.0.0/0"); m.Source = types.StringValue("x"); return m }(),
		"bad protocol":             ingress("http", "0.0.0.0/0"),
		"bad target":               ingress("tcp", "Not A CIDR"),
		"ports on icmp":            portsOnICMP,
		"icmp on tcp":              icmpOnTCP,
		"code without type":        codeWithoutType,
		"reversed ports":           reversedPorts,
	}
	for name, m := range cases {
		if _, err := m.toRule(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestTargetTypes(t *testing.T) {
	cases := map[string]string{
		"10.0.0.0/16":                     targetCIDR,
		"2001:db8::/32":                   targetCIDR,
		"ocid1.networksecuritygroup.oc1.": targetNSG,
		"oci-fra-objectstorage":           targetService,
	}
	for in, want := range cases {
		if _, got, err := parseTarget(in); err != nil || got != want {
			t.Errorf("parseTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestRuleRoundTripThroughOCI(t *testing.T) {
	m := ingress("udp", "10.0.0.0/8")
	m.Ports = types.StringValue("53")
	m.Description = types.StringValue("dns")
	want := mustRule(t, m)

	d := want.toAddDetails()
	got, err := ruleFromOCI(core.SecurityRule{
		Id:          common.String("rule-1"),
		Direction:   core.SecurityRuleDirectionEnum(d.Direction),
		Protocol:    d.Protocol,
		Source:      d.Source,
		SourceType:  core.SecurityRuleSourceTypeEnum(d.SourceType),
		UdpOptions:  d.UdpOptions,
		Description: d.Description,
		IsStateless: d.IsStateless,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Rule, want) {
		t.Errorf("round trip = %+v, want %+v", got.Rule, want)
	}
}

func TestDiffRules(t *testing.T) {
	https := ingress("tcp", "0.0.0.0/0")
	https.Ports = types.StringValue("443")
	ssh := ingress("tcp", "10.0.1.0/24")
	ssh.Ports = types.StringValue("22")
	out := egress("all", "0.0.0.0/0")

	httpsRule := mustRule(t, https)
	sshRule := mustRule(t, ssh)
	outRule := mustRule(t, out)

	sshDescribed := sshRule
	sshDescribed.Description = "bastion"

	live := []liveRule{
		{ID: "https", Rule: httpsRule},
		{ID: "https-dup", Rule: httpsRule},
		{ID: "ssh", Rule: sshRule},
		{ID: "manual", Rule: outRule},
	}
	desired := []nsgRule{httpsRule, sshDescribed, mustRule(t, egress("all", "10.0.0.0/8"))}

	c := diffRules(desired, live)

	if len(c.Add) != 1 || c.Add[0].Target != "10.0.0.0/8" {
		t.Errorf("Add = %+v", c.Add)
	}
	if len(c.Update) != 1 || c.Update[0].ID != "ssh" || c.Update[0].Rule.Description != "bastion" {
		t.Errorf("Update = %+v", c.Update)
	}
	if want := []string{"https-dup", "manual"}; !reflect.DeepEqual(c.Remove, want) {
		t.Errorf("Remove = %v, want %v", c.Remove, want)
	}
}

func TestStateRulesKeepsUserSpelling(t *testing.T) {
	prior := ingress("6", "10.0.1.0/24")
	prior.Ports = types.StringValue("443-443")
	live := mustRule(t, prior)
	live.Description = "changed in console"

	manual := mustRule(t, egress("all", "0.0.0.0/0"))

	models, dups := stateRules([]nsgRuleModel{prior}, []liveRule{
		{ID: "a", Rule: live},
		{ID: "b", Rule: manual},
		{ID: "c", Rule: manual},
	})

	if len(models) != 2 {
		t.Fatalf("got %d models, want 2", len(models))
	}
	if models[0].Protocol.ValueString() != "6" || models[0].Ports.ValueString() != "443-443" {
		t.Errorf("prior spelling lost: %+v", models[0])
	}
	if models[0].Description.ValueString() != "changed in console" {
		t.Errorf("description drift not reported: %+v", models[0])
	}
	if models[1].Protocol.ValueString() != "all" || models[1].Destination.ValueString() != "0.0.0.0/0" {
		t.Errorf("canonical model wrong: %+v", models[1])
	}
	if len(dups) != 1 {
		t.Errorf("duplicates = %v, want one", dups)
	}
}

func TestChunks(t *testing.T) {
	s := make([]int, 60)
	got := chunks(s, maxRulesPerCall)
	if len(got) != 3 || len(got[0]) != 25 || len(got[2]) != 10 {
		t.Errorf("chunks sizes wrong: %d batches", len(got))
	}
}
