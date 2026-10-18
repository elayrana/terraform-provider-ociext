// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// Code shared by ociext_nsg and ociext_nsg_peer_rules. Both manage a set of
// rules of one NSG; peers selects which part: rules that point to an NSG
// (ociext_nsg_peer_rules) or every other rule (ociext_nsg).

var nsgRuleObjectType = types.ObjectType{AttrTypes: nsgRuleAttrTypes}

var protocolDescription = func() string {
	var names []string
	for _, name := range protocolNameList() {
		names = append(names, fmt.Sprintf("`%s` (%s)", name, protocolNumbers[name]))
	}
	return fmt.Sprintf("`all`, a protocol name or an IANA protocol number between %d and %d. Names: %s. "+
		"Ports are only allowed with `tcp` and `udp`, and ICMP type and code with `icmp` and `icmpv6`. "+
		"A rule keeps the spelling used in the configuration, so `gre` and `47` are the same rule.",
		minProtocolNumber, maxProtocolNumber, strings.Join(names, ", "))
}()

func rulesAttribute(peers bool) schema.SetNestedAttribute {
	description := "Security rules of the NSG whose source or destination is a CIDR block or a service. " +
		"Rules that point to an NSG go in `ociext_nsg_peer_rules`."
	targets := "A CIDR block or a service CIDR label (e.g. `all-fra-services-in-oracle-services-network`)."
	if peers {
		description = "Security rules of the NSG whose source or destination is an NSG."
		targets = "OCID of an NSG. It can be the NSG of `nsg_id` itself."
	}

	return schema.SetNestedAttribute{
		MarkdownDescription: description,
		Optional:            !peers,
		Required:            peers,
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"direction": schema.StringAttribute{
					MarkdownDescription: "`INGRESS` or `EGRESS`.",
					Required:            true,
					Validators: []validator.String{
						stringvalidator.OneOf(directionIngress, directionEgress),
					},
				},
				"protocol": schema.StringAttribute{
					MarkdownDescription: protocolDescription,
					Required:            true,
				},
				"source": schema.StringAttribute{
					MarkdownDescription: "Required for `INGRESS`. " + targets,
					Optional:            true,
				},
				"destination": schema.StringAttribute{
					MarkdownDescription: "Required for `EGRESS`. Same formats as `source`.",
					Optional:            true,
				},
				"ports": schema.StringAttribute{
					MarkdownDescription: "Destination port (`443`) or range (`8000-8100`). Only for `tcp` and `udp`; all ports when not set.",
					Optional:            true,
				},
				"source_ports": schema.StringAttribute{
					MarkdownDescription: "Source port or range. Only for `tcp` and `udp`; all ports when not set.",
					Optional:            true,
				},
				"icmp_type": schema.Int64Attribute{
					MarkdownDescription: "ICMP type. Only for `icmp` and `icmpv6`; all types when not set.",
					Optional:            true,
				},
				"icmp_code": schema.Int64Attribute{
					MarkdownDescription: "ICMP code. Needs `icmp_type`; all codes when not set.",
					Optional:            true,
				},
				"description": schema.StringAttribute{
					MarkdownDescription: "Description. Changing it updates the rule in place.",
					Optional:            true,
				},
				"stateless": schema.BoolAttribute{
					MarkdownDescription: "Whether the rule is stateless. Defaults to `false`. Changing it updates the rule in place.",
					Optional:            true,
					Computed:            true,
					Default:             booldefault.StaticBool(false),
				},
			},
		},
	}
}

// validateRules checks every known rule and rejects two rules that match the same traffic.
// Rules that reference a resource not created yet are unknown here; desiredRules checks them at apply.
func validateRules(ctx context.Context, rules types.Set, peers bool) diag.Diagnostics {
	var diags diag.Diagnostics
	if rules.IsNull() || rules.IsUnknown() {
		return diags
	}

	seen := map[string]bool{}
	for _, elem := range rules.Elements() {
		obj, ok := elem.(types.Object)
		if !ok || obj.IsUnknown() {
			continue
		}
		var m nsgRuleModel
		d := obj.As(ctx, &m, basetypes.ObjectAsOptions{})
		diags.Append(d...)
		if d.HasError() {
			return diags
		}
		if !m.isFullyKnown() {
			continue
		}

		rule, err := m.toRule()
		if err == nil {
			err = rule.checkScope(peers)
		}
		if err != nil {
			diags.AddAttributeError(path.Root("rules"), "Invalid NSG rule", err.Error())
			continue
		}
		k := rule.key()
		if seen[k] {
			diags.AddAttributeError(path.Root("rules"), "Duplicate NSG rule",
				fmt.Sprintf("More than one rule matches the same traffic (%s). Only description or stateless differ; keep one of them.", k))
		}
		seen[k] = true
	}
	return diags
}

// desiredRules converts the planned rules set. Values are always known at apply time.
func desiredRules(ctx context.Context, set types.Set, peers bool) ([]nsgRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	if set.IsNull() {
		return nil, diags
	}

	var models []nsgRuleModel
	diags.Append(set.ElementsAs(ctx, &models, false)...)
	if diags.HasError() {
		return nil, diags
	}

	rules := make([]nsgRule, 0, len(models))
	for _, m := range models {
		rule, err := m.toRule()
		if err == nil {
			err = rule.checkScope(peers)
		}
		if err != nil {
			diags.AddAttributeError(path.Root("rules"), "Invalid NSG rule", err.Error())
			continue
		}
		rules = append(rules, rule)
	}
	return rules, diags
}

// checkRuleLimit fails the plan instead of letting OCI fail halfway through an apply.
func checkRuleLimit(ctx context.Context, plan tfsdk.Plan, limit int) diag.Diagnostics {
	var diags diag.Diagnostics
	if plan.Raw.IsNull() {
		return diags
	}

	var rules types.Set
	diags.Append(plan.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if diags.HasError() || rules.IsUnknown() {
		return diags
	}

	if n := len(rules.Elements()); n > limit {
		diags.AddAttributeError(path.Root("rules"), "Too many NSG rules",
			fmt.Sprintf("The NSG has %d rules and the limit is %d. Split the rules across several NSGs, or set max_rules_per_nsg in the provider if your tenancy has a higher limit.",
				n, limit))
	}
	return diags
}

// rulesToState converts the live rules to the rules set stored in state.
func rulesToState(ctx context.Context, prior types.Set, live []liveRule, nsgID string) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics
	var priorModels []nsgRuleModel
	if !prior.IsNull() && !prior.IsUnknown() {
		diags.Append(prior.ElementsAs(ctx, &priorModels, false)...)
	}

	models, duplicates := stateRules(priorModels, live)
	for _, k := range duplicates {
		diags.AddWarning("Duplicate NSG rule in OCI",
			fmt.Sprintf("NSG %s has more than one rule matching %s. The extra copies are removed on the next apply that changes the rules.", nsgID, k))
	}

	if len(models) == 0 && prior.IsNull() {
		return prior, diags
	}
	if models == nil {
		models = []nsgRuleModel{}
	}
	set, d := types.SetValueFrom(ctx, nsgRuleObjectType, models)
	diags.Append(d...)
	return set, diags
}

func (d *providerData) listRules(ctx context.Context, nsgID string) ([]liveRule, error) {
	var out []liveRule
	req := core.ListNetworkSecurityGroupSecurityRulesRequest{NetworkSecurityGroupId: common.String(nsgID)}
	for {
		page, err := d.network.ListNetworkSecurityGroupSecurityRules(ctx, req)
		if err != nil {
			return nil, err
		}
		for _, s := range page.Items {
			l, err := ruleFromOCI(s)
			if err != nil {
				return nil, err
			}
			out = append(out, l)
		}
		if page.OpcNextPage == nil {
			return out, nil
		}
		req.Page = page.OpcNextPage
	}
}

// applyRuleChanges applies the changes to an NSG that has count rules in OCI, in
// the order of planRuleSteps.
func (d *providerData) applyRuleChanges(ctx context.Context, nsgID string, c ruleChanges, count int) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Info(ctx, "Applying NSG rule changes", map[string]any{
		"id": nsgID, "add": len(c.Add), "update": len(c.Update), "remove": len(c.Remove),
	})

	for _, step := range planRuleSteps(c, count, d.maxRulesPerNSG) {
		var err error
		switch {
		case len(step.Add) > 0:
			details := make([]core.AddSecurityRuleDetails, len(step.Add))
			for i, rule := range step.Add {
				details[i] = rule.toAddDetails()
			}
			_, err = d.network.AddNetworkSecurityGroupSecurityRules(ctx, core.AddNetworkSecurityGroupSecurityRulesRequest{
				NetworkSecurityGroupId:                      common.String(nsgID),
				AddNetworkSecurityGroupSecurityRulesDetails: core.AddNetworkSecurityGroupSecurityRulesDetails{SecurityRules: details},
			})
			if err != nil {
				diags.AddError("Unable to add NSG rules", err.Error())
			}
		case len(step.Update) > 0:
			details := make([]core.UpdateSecurityRuleDetails, len(step.Update))
			for i, l := range step.Update {
				details[i] = l.Rule.toUpdateDetails(l.ID)
			}
			_, err = d.network.UpdateNetworkSecurityGroupSecurityRules(ctx, core.UpdateNetworkSecurityGroupSecurityRulesRequest{
				NetworkSecurityGroupId:                         common.String(nsgID),
				UpdateNetworkSecurityGroupSecurityRulesDetails: core.UpdateNetworkSecurityGroupSecurityRulesDetails{SecurityRules: details},
			})
			if err != nil {
				diags.AddError("Unable to update NSG rules", err.Error())
			}
		default:
			_, err = d.network.RemoveNetworkSecurityGroupSecurityRules(ctx, core.RemoveNetworkSecurityGroupSecurityRulesRequest{
				NetworkSecurityGroupId:                         common.String(nsgID),
				RemoveNetworkSecurityGroupSecurityRulesDetails: core.RemoveNetworkSecurityGroupSecurityRulesDetails{SecurityRuleIds: step.Remove},
			})
			if err != nil {
				diags.AddError("Unable to remove NSG rules", err.Error())
			}
		}
		if err != nil {
			return diags
		}
	}

	return diags
}

// configuredData extracts the provider data handed to a resource's Configure.
func configuredData(v any, diags *diag.Diagnostics) *providerData {
	// Nil until the provider has been configured.
	if v == nil {
		return nil
	}
	data, ok := v.(*providerData)
	if !ok {
		diags.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *providerData, got: %T. Please report this issue to the provider developers.", v),
		)
		return nil
	}
	return data
}
