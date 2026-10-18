// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// maxRulesPerCall is the OCI limit of rules per add, update or remove call.
const maxRulesPerCall = 25

const (
	directionIngress = "INGRESS"
	directionEgress  = "EGRESS"

	targetCIDR    = "CIDR_BLOCK"
	targetService = "SERVICE_CIDR_BLOCK"
	targetNSG     = "NETWORK_SECURITY_GROUP"

	protocolAll    = "all"
	protocolICMP   = "1"
	protocolTCP    = "6"
	protocolUDP    = "17"
	protocolICMPv6 = "58"
)

// protocolNames are the protocols that can be written by name. Any other
// protocol is written as its IANA number.
var protocolNames = map[string]string{
	protocolAll:    "all",
	protocolICMP:   "icmp",
	"4":            "ipip",
	protocolTCP:    "tcp",
	protocolUDP:    "udp",
	"47":           "gre",
	"50":           "esp",
	"51":           "ah",
	protocolICMPv6: "icmpv6",
	"89":           "ospf",
	"112":          "vrrp",
	"132":          "sctp",
}

var protocolNumbers = func() map[string]string {
	m := make(map[string]string, len(protocolNames))
	for number, name := range protocolNames {
		m[name] = number
	}
	return m
}()

var serviceCIDRLabel = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// nsgRuleModel is one element of the rules set as Terraform sees it.
type nsgRuleModel struct {
	Direction   types.String `tfsdk:"direction"`
	Protocol    types.String `tfsdk:"protocol"`
	Source      types.String `tfsdk:"source"`
	Destination types.String `tfsdk:"destination"`
	Ports       types.String `tfsdk:"ports"`
	SourcePorts types.String `tfsdk:"source_ports"`
	IcmpType    types.Int64  `tfsdk:"icmp_type"`
	IcmpCode    types.Int64  `tfsdk:"icmp_code"`
	Description types.String `tfsdk:"description"`
	Stateless   types.Bool   `tfsdk:"stateless"`
}

var nsgRuleAttrTypes = map[string]attr.Type{
	"direction":    types.StringType,
	"protocol":     types.StringType,
	"source":       types.StringType,
	"destination":  types.StringType,
	"ports":        types.StringType,
	"source_ports": types.StringType,
	"icmp_type":    types.Int64Type,
	"icmp_code":    types.Int64Type,
	"description":  types.StringType,
	"stateless":    types.BoolType,
}

func (m nsgRuleModel) isFullyKnown() bool {
	values := []attr.Value{
		m.Direction, m.Protocol, m.Source, m.Destination, m.Ports,
		m.SourcePorts, m.IcmpType, m.IcmpCode, m.Description, m.Stateless,
	}
	for _, v := range values {
		if v.IsUnknown() {
			return false
		}
	}
	return true
}

type portRange struct {
	Min, Max int
}

func (p portRange) String() string {
	if p.Min == p.Max {
		return strconv.Itoa(p.Min)
	}
	return fmt.Sprintf("%d-%d", p.Min, p.Max)
}

// nsgRule is a normalized security rule. Two rules that let through the same
// traffic always produce the same key, whatever way they were written.
type nsgRule struct {
	Direction  string
	Protocol   string // "all" or the IANA protocol number
	Target     string // source for INGRESS, destination for EGRESS
	TargetType string
	DstPorts   *portRange
	SrcPorts   *portRange
	IcmpType   *int
	IcmpCode   *int

	// Not part of the key: changing them updates the rule in place.
	Description string
	Stateless   bool
}

// key identifies the traffic a rule matches, e.g. "INGRESS_tcp_0.0.0.0/0_dst:443".
func (r nsgRule) key() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s_%s_%s", r.Direction, protocolDisplay(r.Protocol), r.Target)
	if r.SrcPorts != nil {
		fmt.Fprintf(&b, "_src:%s", r.SrcPorts)
	}
	if r.DstPorts != nil {
		fmt.Fprintf(&b, "_dst:%s", r.DstPorts)
	}
	if r.IcmpType != nil {
		fmt.Fprintf(&b, "_icmp:%d", *r.IcmpType)
		if r.IcmpCode != nil {
			fmt.Fprintf(&b, "-%d", *r.IcmpCode)
		}
	}
	return b.String()
}

func protocolDisplay(number string) string {
	if name, ok := protocolNames[number]; ok {
		return name
	}
	return number
}

// OCI accepts the IANA protocol numbers 1 to 254: it rejects 0 (HOPOPT) and 255 (reserved).
const (
	minProtocolNumber = 1
	maxProtocolNumber = 254
)

func parseProtocol(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if n, ok := protocolNumbers[v]; ok {
		return n, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < minProtocolNumber || n > maxProtocolNumber {
		return "", fmt.Errorf("protocol %q must be all, a protocol name (%s) or a number between %d and %d",
			v, strings.Join(protocolNameList(), ", "), minProtocolNumber, maxProtocolNumber)
	}
	return strconv.Itoa(n), nil
}

// protocolNameList returns the protocol names other than all, sorted by number.
func protocolNameList() []string {
	numbers := make([]int, 0, len(protocolNames))
	for number := range protocolNames {
		if n, err := strconv.Atoi(number); err == nil {
			numbers = append(numbers, n)
		}
	}
	sort.Ints(numbers)
	names := make([]string, len(numbers))
	for i, n := range numbers {
		names[i] = protocolNames[strconv.Itoa(n)]
	}
	return names
}

func parsePorts(v string) (*portRange, error) {
	lo, hi, isRange := strings.Cut(strings.TrimSpace(v), "-")
	if !isRange {
		hi = lo
	}
	minPort, err1 := strconv.Atoi(strings.TrimSpace(lo))
	maxPort, err2 := strconv.Atoi(strings.TrimSpace(hi))
	if err1 != nil || err2 != nil || minPort < 1 || maxPort > 65535 || minPort > maxPort {
		return nil, fmt.Errorf("ports %q must be a port (443) or a range (8000-8100) between 1 and 65535", v)
	}
	return &portRange{Min: minPort, Max: maxPort}, nil
}

// parseTarget deduces the source or destination type from its value.
func parseTarget(v string) (value, kind string, err error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "ocid1.networksecuritygroup.") {
		return v, targetNSG, nil
	}
	if prefix, err := netip.ParsePrefix(v); err == nil {
		return prefix.Masked().String(), targetCIDR, nil
	}
	if serviceCIDRLabel.MatchString(v) {
		return v, targetService, nil
	}
	return "", "", fmt.Errorf("%q is not a CIDR block, an NSG OCID or a service CIDR label", v)
}

// isPeer reports whether the rule points to an NSG. Those rules belong to
// ociext_nsg_peer_rules and every other rule to ociext_nsg, so that NSGs can
// reference each other (or themselves) without a dependency cycle.
func (r nsgRule) isPeer() bool { return r.TargetType == targetNSG }

// checkScope rejects a rule that belongs to the other resource.
func (r nsgRule) checkScope(peers bool) error {
	switch {
	case peers && !r.isPeer():
		return fmt.Errorf("%s does not point to an NSG: rules with a CIDR block or a service go in the rules of ociext_nsg", r.key())
	case !peers && r.isPeer():
		return fmt.Errorf("%s points to an NSG: those rules go in ociext_nsg_peer_rules, so that NSGs can reference each other without a dependency cycle", r.key())
	}
	return nil
}

// inScope keeps the live rules managed by ociext_nsg_peer_rules (peers) or by ociext_nsg.
func inScope(live []liveRule, peers bool) []liveRule {
	var out []liveRule
	for _, l := range live {
		if l.Rule.isPeer() == peers {
			out = append(out, l)
		}
	}
	return out
}

// foreignRules returns the keys of the live rules that are not in desired.
func foreignRules(desired []nsgRule, live []liveRule) []string {
	wanted := map[string]bool{}
	for _, d := range desired {
		wanted[d.key()] = true
	}
	var keys []string
	for _, l := range live {
		if k := l.Rule.key(); !wanted[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func isPortProtocol(p string) bool { return p == protocolTCP || p == protocolUDP }
func isICMPProtocol(p string) bool { return p == protocolICMP || p == protocolICMPv6 }

// toRule validates and normalizes a rule written in Terraform. The model must be fully known.
func (m nsgRuleModel) toRule() (nsgRule, error) {
	r := nsgRule{
		Direction:   m.Direction.ValueString(),
		Description: m.Description.ValueString(),
		Stateless:   m.Stateless.ValueBool(),
	}

	var err error
	if r.Protocol, err = parseProtocol(m.Protocol.ValueString()); err != nil {
		return r, err
	}

	switch r.Direction {
	case directionIngress:
		if m.Source.IsNull() || !m.Destination.IsNull() {
			return r, fmt.Errorf("INGRESS rules need source and must not set destination")
		}
		r.Target, r.TargetType, err = parseTarget(m.Source.ValueString())
	case directionEgress:
		if m.Destination.IsNull() || !m.Source.IsNull() {
			return r, fmt.Errorf("EGRESS rules need destination and must not set source")
		}
		r.Target, r.TargetType, err = parseTarget(m.Destination.ValueString())
	default:
		return r, fmt.Errorf("direction %q must be INGRESS or EGRESS", r.Direction)
	}
	if err != nil {
		return r, err
	}

	if !m.Ports.IsNull() || !m.SourcePorts.IsNull() {
		if !isPortProtocol(r.Protocol) {
			return r, fmt.Errorf("ports and source_ports are only allowed with tcp or udp")
		}
		if !m.Ports.IsNull() {
			if r.DstPorts, err = parsePorts(m.Ports.ValueString()); err != nil {
				return r, err
			}
		}
		if !m.SourcePorts.IsNull() {
			if r.SrcPorts, err = parsePorts(m.SourcePorts.ValueString()); err != nil {
				return r, err
			}
		}
	}

	if !m.IcmpType.IsNull() || !m.IcmpCode.IsNull() {
		if !isICMPProtocol(r.Protocol) {
			return r, fmt.Errorf("icmp_type and icmp_code are only allowed with icmp or icmpv6")
		}
		if m.IcmpType.IsNull() {
			return r, fmt.Errorf("icmp_code needs icmp_type")
		}
		t := int(m.IcmpType.ValueInt64())
		if t < 0 || t > 255 {
			return r, fmt.Errorf("icmp_type must be between 0 and 255")
		}
		r.IcmpType = &t
		if !m.IcmpCode.IsNull() {
			c := int(m.IcmpCode.ValueInt64())
			if c < 0 || c > 255 {
				return r, fmt.Errorf("icmp_code must be between 0 and 255")
			}
			r.IcmpCode = &c
		}
	}

	return r, nil
}

// toModel renders a rule in its canonical Terraform form, used when there is
// no prior state to copy the user's spelling from (import, rules added outside Terraform).
func (r nsgRule) toModel() nsgRuleModel {
	m := nsgRuleModel{
		Direction:   types.StringValue(r.Direction),
		Protocol:    types.StringValue(protocolDisplay(r.Protocol)),
		Source:      types.StringNull(),
		Destination: types.StringNull(),
		Ports:       types.StringNull(),
		SourcePorts: types.StringNull(),
		IcmpType:    types.Int64Null(),
		IcmpCode:    types.Int64Null(),
		Description: types.StringNull(),
		Stateless:   types.BoolValue(r.Stateless),
	}
	if r.Direction == directionIngress {
		m.Source = types.StringValue(r.Target)
	} else {
		m.Destination = types.StringValue(r.Target)
	}
	if r.DstPorts != nil {
		m.Ports = types.StringValue(r.DstPorts.String())
	}
	if r.SrcPorts != nil {
		m.SourcePorts = types.StringValue(r.SrcPorts.String())
	}
	if r.IcmpType != nil {
		m.IcmpType = types.Int64Value(int64(*r.IcmpType))
	}
	if r.IcmpCode != nil {
		m.IcmpCode = types.Int64Value(int64(*r.IcmpCode))
	}
	if r.Description != "" {
		m.Description = types.StringValue(r.Description)
	}
	return m
}

// liveRule is a rule as it exists in OCI.
type liveRule struct {
	ID   string
	Rule nsgRule
}

func ruleFromOCI(s core.SecurityRule) (liveRule, error) {
	r := nsgRule{
		Direction:   string(s.Direction),
		Description: deref(s.Description),
		Stateless:   s.IsStateless != nil && *s.IsStateless,
	}
	id := deref(s.Id)

	var err error
	if r.Protocol, err = parseProtocol(deref(s.Protocol)); err != nil {
		return liveRule{}, fmt.Errorf("rule %s: %w", id, err)
	}

	target := s.Source
	if r.Direction == directionEgress {
		target = s.Destination
	}
	if r.Target, r.TargetType, err = parseTarget(deref(target)); err != nil {
		return liveRule{}, fmt.Errorf("rule %s: %w", id, err)
	}

	var src, dst *core.PortRange
	switch {
	case s.TcpOptions != nil:
		src, dst = s.TcpOptions.SourcePortRange, s.TcpOptions.DestinationPortRange
	case s.UdpOptions != nil:
		src, dst = s.UdpOptions.SourcePortRange, s.UdpOptions.DestinationPortRange
	}
	r.SrcPorts = portRangeFromOCI(src)
	r.DstPorts = portRangeFromOCI(dst)

	if s.IcmpOptions != nil {
		r.IcmpType = s.IcmpOptions.Type
		r.IcmpCode = s.IcmpOptions.Code
	}

	return liveRule{ID: id, Rule: r}, nil
}

func portRangeFromOCI(p *core.PortRange) *portRange {
	if p == nil || p.Min == nil || p.Max == nil {
		return nil
	}
	return &portRange{Min: *p.Min, Max: *p.Max}
}

func (p *portRange) toOCI() *core.PortRange {
	if p == nil {
		return nil
	}
	return &core.PortRange{Min: common.Int(p.Min), Max: common.Int(p.Max)}
}

// ociFields builds the parts shared by the add and update request bodies.
func (r nsgRule) ociFields() (source, destination *string, tcp *core.TcpOptions, udp *core.UdpOptions, icmp *core.IcmpOptions) {
	if r.Direction == directionIngress {
		source = common.String(r.Target)
	} else {
		destination = common.String(r.Target)
	}
	if r.DstPorts != nil || r.SrcPorts != nil {
		switch r.Protocol {
		case protocolTCP:
			tcp = &core.TcpOptions{DestinationPortRange: r.DstPorts.toOCI(), SourcePortRange: r.SrcPorts.toOCI()}
		case protocolUDP:
			udp = &core.UdpOptions{DestinationPortRange: r.DstPorts.toOCI(), SourcePortRange: r.SrcPorts.toOCI()}
		}
	}
	if r.IcmpType != nil {
		icmp = &core.IcmpOptions{Type: r.IcmpType, Code: r.IcmpCode}
	}
	return
}

func (r nsgRule) toAddDetails() core.AddSecurityRuleDetails {
	source, destination, tcp, udp, icmp := r.ociFields()
	d := core.AddSecurityRuleDetails{
		Direction:   core.AddSecurityRuleDetailsDirectionEnum(r.Direction),
		Protocol:    common.String(r.Protocol),
		Source:      source,
		Destination: destination,
		TcpOptions:  tcp,
		UdpOptions:  udp,
		IcmpOptions: icmp,
		IsStateless: common.Bool(r.Stateless),
	}
	if r.Description != "" {
		d.Description = common.String(r.Description)
	}
	if source != nil {
		d.SourceType = core.AddSecurityRuleDetailsSourceTypeEnum(r.TargetType)
	} else {
		d.DestinationType = core.AddSecurityRuleDetailsDestinationTypeEnum(r.TargetType)
	}
	return d
}

func (r nsgRule) toUpdateDetails(id string) core.UpdateSecurityRuleDetails {
	source, destination, tcp, udp, icmp := r.ociFields()
	d := core.UpdateSecurityRuleDetails{
		Id:          common.String(id),
		Direction:   core.UpdateSecurityRuleDetailsDirectionEnum(r.Direction),
		Protocol:    common.String(r.Protocol),
		Source:      source,
		Destination: destination,
		TcpOptions:  tcp,
		UdpOptions:  udp,
		IcmpOptions: icmp,
		IsStateless: common.Bool(r.Stateless),
		// Always sent so that removing a description clears it.
		Description: common.String(r.Description),
	}
	if source != nil {
		d.SourceType = core.UpdateSecurityRuleDetailsSourceTypeEnum(r.TargetType)
	} else {
		d.DestinationType = core.UpdateSecurityRuleDetailsDestinationTypeEnum(r.TargetType)
	}
	return d
}

// ruleChanges is what has to be done in OCI to go from the live rules to the desired ones.
type ruleChanges struct {
	Add    []nsgRule
	Update []liveRule // ID of the live rule with the desired content
	Remove []string
}

func diffRules(desired []nsgRule, live []liveRule) ruleChanges {
	liveByKey := map[string][]liveRule{}
	for _, l := range live {
		k := l.Rule.key()
		liveByKey[k] = append(liveByKey[k], l)
	}

	var c ruleChanges
	wanted := map[string]bool{}
	for _, d := range desired {
		k := d.key()
		wanted[k] = true
		matches := liveByKey[k]
		if len(matches) == 0 {
			c.Add = append(c.Add, d)
			continue
		}
		if matches[0].Rule.Description != d.Description || matches[0].Rule.Stateless != d.Stateless {
			c.Update = append(c.Update, liveRule{ID: matches[0].ID, Rule: d})
		}
		// Identical rules created outside Terraform: keep one.
		for _, dup := range matches[1:] {
			c.Remove = append(c.Remove, dup.ID)
		}
	}
	for k, matches := range liveByKey {
		if wanted[k] {
			continue
		}
		for _, l := range matches {
			c.Remove = append(c.Remove, l.ID)
		}
	}
	sort.Strings(c.Remove)
	return c
}

// stateRules turns the live rules into the set stored in state. Rules that
// were already in the prior state keep the user's spelling (e.g. "tcp" vs "6",
// "443" vs "443-443") so that refresh only reports real changes.
func stateRules(prior []nsgRuleModel, live []liveRule) (models []nsgRuleModel, duplicates []string) {
	priorByKey := map[string]nsgRuleModel{}
	for _, m := range prior {
		if r, err := m.toRule(); err == nil {
			priorByKey[r.key()] = m
		}
	}

	seen := map[string]bool{}
	for _, l := range live {
		k := l.Rule.key()
		if seen[k] {
			duplicates = append(duplicates, k)
			continue
		}
		seen[k] = true

		m, ok := priorByKey[k]
		if !ok {
			models = append(models, l.Rule.toModel())
			continue
		}
		if l.Rule.Description != m.Description.ValueString() {
			m.Description = types.StringValue(l.Rule.Description)
			if l.Rule.Description == "" {
				m.Description = types.StringNull()
			}
		}
		m.Stateless = types.BoolValue(l.Rule.Stateless)
		models = append(models, m)
	}
	return models, duplicates
}

func chunks[T any](s []T, size int) [][]T {
	var out [][]T
	for size < len(s) {
		out = append(out, s[:size])
		s = s[size:]
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
