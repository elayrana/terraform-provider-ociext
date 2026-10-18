// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"reflect"
	"strings"
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

	dns := egress("udp", "10.0.0.0/16")
	dns.Ports = types.StringValue("53")

	cases := map[string]nsgRuleModel{
		"INGRESS_tcp_0.0.0.0/0_dst:443":                          https,
		"INGRESS_icmp_10.0.0.0/8_icmp:3-4":                       icmp,
		"INGRESS_tcp_10.0.1.0/24_src:1024-65535_dst:22":          ssh,
		"EGRESS_udp_10.0.0.0/16_dst:53":                          dns,
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
		"protocol 0":               ingress("0", "0.0.0.0/0"),
		"protocol 255":             ingress("255", "0.0.0.0/0"),
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

func TestRuleScope(t *testing.T) {
	const nsg = "ocid1.networksecuritygroup.oc1.eu-madrid-1.aaaa"
	peer := mustRule(t, ingress("tcp", nsg))
	cidr := mustRule(t, ingress("tcp", "10.0.0.0/8"))
	service := mustRule(t, egress("all", "all-mad-services-in-oracle-services-network"))

	cases := []struct {
		name  string
		rule  nsgRule
		peers bool
		ok    bool
	}{
		{"peer in ociext_nsg", peer, false, false},
		{"peer in peer_rules", peer, true, true},
		{"cidr in ociext_nsg", cidr, false, true},
		{"cidr in peer_rules", cidr, true, false},
		{"service in ociext_nsg", service, false, true},
		{"service in peer_rules", service, true, false},
	}
	for _, c := range cases {
		if err := c.rule.checkScope(c.peers); (err == nil) != c.ok {
			t.Errorf("%s: checkScope = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestInScopeKeepsOtherResourceRules(t *testing.T) {
	peer := mustRule(t, ingress("tcp", "ocid1.networksecuritygroup.oc1.eu-madrid-1.bbbb"))
	cidr := mustRule(t, ingress("tcp", "10.0.0.0/8"))
	live := []liveRule{{ID: "peer", Rule: peer}, {ID: "cidr", Rule: cidr}}

	if got := inScope(live, true); len(got) != 1 || got[0].ID != "peer" {
		t.Errorf("inScope(peers) = %+v", got)
	}
	if got := inScope(live, false); len(got) != 1 || got[0].ID != "cidr" {
		t.Errorf("inScope(ociext_nsg) = %+v", got)
	}

	// ociext_nsg with no rules must not remove the peer rule, and the other way round.
	if c := diffRules(nil, inScope(live, false)); !reflect.DeepEqual(c.Remove, []string{"cidr"}) {
		t.Errorf("ociext_nsg Remove = %v", c.Remove)
	}
	if c := diffRules(nil, inScope(live, true)); !reflect.DeepEqual(c.Remove, []string{"peer"}) {
		t.Errorf("peer_rules Remove = %v", c.Remove)
	}
}

func TestForeignRules(t *testing.T) {
	const nsgA = "ocid1.networksecuritygroup.oc1.eu-madrid-1.aaaa"
	const nsgB = "ocid1.networksecuritygroup.oc1.eu-madrid-1.bbbb"
	ours := mustRule(t, ingress("tcp", nsgA))
	theirs := mustRule(t, ingress("all", nsgB))

	ourCopy := ours
	ourCopy.Description = "same traffic, other description"
	live := []liveRule{{ID: "1", Rule: ourCopy}, {ID: "2", Rule: theirs}}

	got := foreignRules([]nsgRule{ours}, live)
	if want := []string{theirs.key()}; !reflect.DeepEqual(got, want) {
		t.Errorf("foreignRules = %v, want %v", got, want)
	}
	if got := foreignRules([]nsgRule{ours, theirs}, live); len(got) != 0 {
		t.Errorf("foreignRules with all rules desired = %v, want none", got)
	}
}

func TestProtocolNames(t *testing.T) {
	cases := map[string]string{"all": "all", "IPIP": "4", "gre": "47", "esp": "50", "ah": "51", "ospf": "89", "vrrp": "112", "sctp": "132", "1": "1", "254": "254"}
	for in, want := range cases {
		if got, err := parseProtocol(in); err != nil || got != want {
			t.Errorf("parseProtocol(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	// A name and its number are the same rule.
	byName := ingress("gre", "10.0.0.0/8")
	byNumber := ingress("47", "10.0.0.0/8")
	if a, b := mustRule(t, byName).key(), mustRule(t, byNumber).key(); a != b || a != "INGRESS_gre_10.0.0.0/8" {
		t.Errorf("keys = %q, %q; want both INGRESS_gre_10.0.0.0/8", a, b)
	}
}

func TestOptionsAllowedByProtocol(t *testing.T) {
	type option int
	const (
		ports option = iota
		sourcePorts
		icmpType
		icmpCode
	)
	with := func(protocol string, o option) nsgRuleModel {
		m := ingress(protocol, "10.0.0.0/8")
		switch o {
		case ports:
			m.Ports = types.StringValue("443")
		case sourcePorts:
			m.SourcePorts = types.StringValue("1024-65535")
		case icmpType:
			m.IcmpType = types.Int64Value(3)
		case icmpCode:
			m.IcmpType = types.Int64Value(3)
			m.IcmpCode = types.Int64Value(4)
		}
		return m
	}

	allowed := map[option][]string{
		ports:       {"tcp", "udp", "6", "17", "TCP"},
		sourcePorts: {"tcp", "udp", "6", "17"},
		icmpType:    {"icmp", "icmpv6", "1", "58"},
		icmpCode:    {"icmp", "icmpv6", "1", "58"},
	}
	rejected := map[option][]string{
		ports:       {"all", "icmp", "icmpv6", "gre", "esp", "sctp", "1", "47", "132"},
		sourcePorts: {"all", "icmp", "icmpv6", "gre", "sctp"},
		icmpType:    {"all", "tcp", "udp", "gre", "6", "17"},
		icmpCode:    {"all", "tcp", "udp", "ipip"},
	}
	names := map[option]string{ports: "ports", sourcePorts: "source_ports", icmpType: "icmp_type", icmpCode: "icmp_code"}

	for o, protocols := range allowed {
		for _, p := range protocols {
			if _, err := with(p, o).toRule(); err != nil {
				t.Errorf("%s with %s: unexpected error %v", names[o], p, err)
			}
		}
	}
	for o, protocols := range rejected {
		for _, p := range protocols {
			if _, err := with(p, o).toRule(); err == nil {
				t.Errorf("%s with %s: expected an error", names[o], p)
			}
		}
	}
}

func TestPlanRuleSteps(t *testing.T) {
	rules := func(n int) []nsgRule { return make([]nsgRule, n) }
	ids := func(n int) []string { return make([]string, n) }
	// describe turns the steps into e.g. "+25 +5 ~3 -25 -5".
	describe := func(steps []ruleStep) string {
		var out []string
		for _, s := range steps {
			switch {
			case len(s.Add) > 0:
				out = append(out, fmt.Sprintf("+%d", len(s.Add)))
			case len(s.Update) > 0:
				out = append(out, fmt.Sprintf("~%d", len(s.Update)))
			default:
				out = append(out, fmt.Sprintf("-%d", len(s.Remove)))
			}
		}
		return strings.Join(out, " ")
	}

	cases := []struct {
		name         string
		c            ruleChanges
		count, limit int
		want         string
		maxCount     int // highest rule count reached in OCI
	}{
		{"room to spare: adds first", ruleChanges{Add: rules(30), Update: make([]liveRule, 3), Remove: ids(30)}, 50, 120, "+25 +5 ~3 -25 -5", 80},
		{"near the limit: removes to make room", ruleChanges{Add: rules(30), Remove: ids(30)}, 110, 120, "+10 -25 +20 -5", 120},
		{"at the limit", ruleChanges{Add: rules(1), Remove: ids(1)}, 120, 120, "-1 +1", 120},
		{"new NSG", ruleChanges{Add: rules(120)}, 0, 120, "+25 +25 +25 +25 +20", 120},
		{"over the limit with nothing to remove: OCI reports it", ruleChanges{Add: rules(5)}, 120, 120, "+5", 125},
		{"higher tenancy limit", ruleChanges{Add: rules(30), Remove: ids(30)}, 650, 700, "+25 +5 -25 -5", 680},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			steps := planRuleSteps(tc.c, tc.count, tc.limit)
			if got := describe(steps); got != tc.want {
				t.Errorf("steps = %q, want %q", got, tc.want)
			}
			count, highest := tc.count, tc.count
			for _, s := range steps {
				count += len(s.Add) - len(s.Remove)
				highest = max(highest, count)
				if n := len(s.Add) + len(s.Update) + len(s.Remove); n > maxRulesPerCall {
					t.Errorf("step with %d rules, the OCI limit per call is %d", n, maxRulesPerCall)
				}
			}
			if highest != tc.maxCount {
				t.Errorf("highest rule count = %d, want %d", highest, tc.maxCount)
			}
			if want := tc.count + len(tc.c.Add) - len(tc.c.Remove); count != want {
				t.Errorf("final rule count = %d, want %d", count, want)
			}
		})
	}
}
