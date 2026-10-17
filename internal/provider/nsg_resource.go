// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                   = &NSGResource{}
	_ resource.ResourceWithConfigure      = &NSGResource{}
	_ resource.ResourceWithImportState    = &NSGResource{}
	_ resource.ResourceWithValidateConfig = &NSGResource{}
	_ resource.ResourceWithModifyPlan     = &NSGResource{}
)

const nsgWaitTimeout = 10 * time.Minute

var nsgRuleObjectType = types.ObjectType{AttrTypes: nsgRuleAttrTypes}

func NewNSGResource() resource.Resource {
	return &NSGResource{}
}

// NSGResource manages a network security group together with all its rules.
type NSGResource struct {
	data *providerData
}

// NSGResourceModel describes the resource data model.
type NSGResourceModel struct {
	ID            types.String `tfsdk:"id"`
	CompartmentID types.String `tfsdk:"compartment_id"`
	VcnID         types.String `tfsdk:"vcn_id"`
	DisplayName   types.String `tfsdk:"display_name"`
	FreeformTags  types.Map    `tfsdk:"freeform_tags"`
	Rules         types.Set    `tfsdk:"rules"`
}

func (r *NSGResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_nsg"
}

func (r *NSGResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Network security group with all its security rules in a single resource. " +
			"Rules are identified by the traffic they match (direction, protocol, source or destination, ports, ICMP type and code), " +
			"so their order does not matter and adding or removing one only changes that rule. " +
			"The resource owns every rule of the NSG: rules created outside Terraform are removed on the next apply.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "OCID of the network security group.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"compartment_id": schema.StringAttribute{
				MarkdownDescription: "OCID of the compartment. Changing it moves the NSG without recreating it.",
				Required:            true,
			},
			"vcn_id": schema.StringAttribute{
				MarkdownDescription: "OCID of the VCN. Changing it recreates the NSG.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"display_name": schema.StringAttribute{
				MarkdownDescription: "Display name. OCI generates one when it is not set.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"freeform_tags": schema.MapAttribute{
				MarkdownDescription: "Free-form tags.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"rules": schema.SetNestedAttribute{
				MarkdownDescription: "Security rules of the NSG.",
				Optional:            true,
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
							MarkdownDescription: "`all`, `icmp`, `tcp`, `udp`, `icmpv6` or an IANA protocol number.",
							Required:            true,
						},
						"source": schema.StringAttribute{
							MarkdownDescription: "Required for `INGRESS`. A CIDR block, the OCID of an NSG or a service CIDR label (e.g. `all-fra-services-in-oracle-services-network`).",
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
			},
		},
	}
}

func (r *NSGResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	data, ok := req.ProviderData.(*providerData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *providerData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.data = data
}

// ValidateConfig checks every rule and rejects two rules that match the same traffic.
func (r *NSGResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var rules types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if resp.Diagnostics.HasError() || rules.IsNull() || rules.IsUnknown() {
		return
	}

	seen := map[string]bool{}
	for _, elem := range rules.Elements() {
		obj, ok := elem.(types.Object)
		if !ok || obj.IsUnknown() {
			continue
		}
		var m nsgRuleModel
		diags := obj.As(ctx, &m, basetypes.ObjectAsOptions{})
		resp.Diagnostics.Append(diags...)
		if diags.HasError() {
			return
		}
		if !m.isFullyKnown() {
			continue
		}

		rule, err := m.toRule()
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("rules"), "Invalid NSG rule", err.Error())
			continue
		}
		k := rule.key()
		if seen[k] {
			resp.Diagnostics.AddAttributeError(path.Root("rules"), "Duplicate NSG rule",
				fmt.Sprintf("More than one rule matches the same traffic (%s). Only description or stateless differ; keep one of them.", k))
		}
		seen[k] = true
	}
}

// ModifyPlan enforces the rules-per-NSG limit at plan time instead of failing halfway through an apply.
func (r *NSGResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() || r.data == nil {
		return
	}

	var rules types.Set
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if resp.Diagnostics.HasError() || rules.IsUnknown() {
		return
	}

	if n := len(rules.Elements()); n > r.data.maxRulesPerNSG {
		resp.Diagnostics.AddAttributeError(path.Root("rules"), "Too many NSG rules",
			fmt.Sprintf("The NSG has %d rules and the limit is %d. Split the rules across several NSGs, or set max_rules_per_nsg in the provider if your tenancy has a higher limit.",
				n, r.data.maxRulesPerNSG))
	}
}

func (r *NSGResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan NSGResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	desired, diags := desiredRules(ctx, plan.Rules)
	resp.Diagnostics.Append(diags...)
	tags, diags := freeformTags(ctx, plan.FreeformTags)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	details := core.CreateNetworkSecurityGroupDetails{
		CompartmentId: plan.CompartmentID.ValueStringPointer(),
		VcnId:         plan.VcnID.ValueStringPointer(),
		FreeformTags:  tags,
	}
	if !plan.DisplayName.IsUnknown() && !plan.DisplayName.IsNull() {
		details.DisplayName = plan.DisplayName.ValueStringPointer()
	}

	created, err := r.data.network.CreateNetworkSecurityGroup(ctx, core.CreateNetworkSecurityGroupRequest{
		CreateNetworkSecurityGroupDetails: details,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create NSG", err.Error())
		return
	}
	nsgID := *created.Id
	plan.ID = types.StringValue(nsgID)
	plan.DisplayName = types.StringPointerValue(created.DisplayName)

	// Save the NSG before adding its rules so that a failure leaves it in state (tainted) instead of orphaned.
	saved := plan
	saved.Rules = types.SetNull(nsgRuleObjectType)
	resp.Diagnostics.Append(resp.State.Set(ctx, &saved)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.waitForState(ctx, nsgID, core.NetworkSecurityGroupLifecycleStateAvailable); err != nil {
		resp.Diagnostics.AddError("NSG did not become available", err.Error())
		return
	}

	resp.Diagnostics.Append(r.applyRuleChanges(ctx, nsgID, diffRules(desired, nil))...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NSGResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state NSGResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	nsgID := state.ID.ValueString()
	got, err := r.data.network.GetNetworkSecurityGroup(ctx, core.GetNetworkSecurityGroupRequest{
		NetworkSecurityGroupId: common.String(nsgID),
	})
	if isNotFound(err) || (err == nil && isGone(got.LifecycleState)) {
		tflog.Warn(ctx, "NSG no longer exists, removing it from state", map[string]any{"id": nsgID})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read NSG", err.Error())
		return
	}

	state.CompartmentID = types.StringPointerValue(got.CompartmentId)
	state.VcnID = types.StringPointerValue(got.VcnId)
	state.DisplayName = types.StringPointerValue(got.DisplayName)
	if len(got.FreeformTags) > 0 || !state.FreeformTags.IsNull() {
		tags, diags := types.MapValueFrom(ctx, types.StringType, got.FreeformTags)
		resp.Diagnostics.Append(diags...)
		state.FreeformTags = tags
	}

	live, err := r.listRules(ctx, nsgID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read NSG rules", err.Error())
		return
	}

	var prior []nsgRuleModel
	if !state.Rules.IsNull() && !state.Rules.IsUnknown() {
		resp.Diagnostics.Append(state.Rules.ElementsAs(ctx, &prior, false)...)
	}
	models, duplicates := stateRules(prior, live)
	for _, k := range duplicates {
		resp.Diagnostics.AddWarning("Duplicate NSG rule in OCI",
			fmt.Sprintf("NSG %s has more than one rule matching %s. The extra copies are removed on the next apply that changes the rules.", nsgID, k))
	}

	if len(models) > 0 || !state.Rules.IsNull() {
		rules, diags := types.SetValueFrom(ctx, nsgRuleObjectType, models)
		resp.Diagnostics.Append(diags...)
		state.Rules = rules
	}
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *NSGResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state NSGResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	nsgID := state.ID.ValueString()

	if !plan.CompartmentID.Equal(state.CompartmentID) {
		_, err := r.data.network.ChangeNetworkSecurityGroupCompartment(ctx, core.ChangeNetworkSecurityGroupCompartmentRequest{
			NetworkSecurityGroupId: common.String(nsgID),
			ChangeNetworkSecurityGroupCompartmentDetails: core.ChangeNetworkSecurityGroupCompartmentDetails{
				CompartmentId: plan.CompartmentID.ValueStringPointer(),
			},
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to move NSG to another compartment", err.Error())
			return
		}
	}

	if !plan.DisplayName.Equal(state.DisplayName) || !plan.FreeformTags.Equal(state.FreeformTags) {
		tags, diags := freeformTags(ctx, plan.FreeformTags)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		if tags == nil {
			tags = map[string]string{} // clears the tags removed from the config
		}
		updated, err := r.data.network.UpdateNetworkSecurityGroup(ctx, core.UpdateNetworkSecurityGroupRequest{
			NetworkSecurityGroupId: common.String(nsgID),
			UpdateNetworkSecurityGroupDetails: core.UpdateNetworkSecurityGroupDetails{
				DisplayName:  plan.DisplayName.ValueStringPointer(),
				FreeformTags: tags,
			},
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to update NSG", err.Error())
			return
		}
		plan.DisplayName = types.StringPointerValue(updated.DisplayName)
	}

	if !plan.Rules.Equal(state.Rules) {
		desired, diags := desiredRules(ctx, plan.Rules)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		// Diff against OCI, not against state, so the apply also fixes changes made since the last refresh.
		live, err := r.listRules(ctx, nsgID)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read NSG rules", err.Error())
			return
		}
		resp.Diagnostics.Append(r.applyRuleChanges(ctx, nsgID, diffRules(desired, live))...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NSGResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state NSGResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	nsgID := state.ID.ValueString()

	// Deleting the NSG deletes its rules too.
	_, err := r.data.network.DeleteNetworkSecurityGroup(ctx, core.DeleteNetworkSecurityGroupRequest{
		NetworkSecurityGroupId: common.String(nsgID),
	})
	if isNotFound(err) {
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to delete NSG",
			fmt.Sprintf("%s\n\nAn NSG can only be deleted once no VNIC or other resource uses it.", err))
		return
	}

	if err := r.waitForState(ctx, nsgID, core.NetworkSecurityGroupLifecycleStateTerminated); err != nil {
		resp.Diagnostics.AddError("NSG was not deleted", err.Error())
	}
}

func (r *NSGResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// applyRuleChanges adds new rules before removing old ones, so a rule that is
// replaced (its traffic changed) never leaves a gap without access.
func (r *NSGResource) applyRuleChanges(ctx context.Context, nsgID string, c ruleChanges) diag.Diagnostics {
	var diags diag.Diagnostics
	tflog.Info(ctx, "Applying NSG rule changes", map[string]any{
		"id": nsgID, "add": len(c.Add), "update": len(c.Update), "remove": len(c.Remove),
	})

	for _, batch := range chunks(c.Add, maxRulesPerCall) {
		details := make([]core.AddSecurityRuleDetails, len(batch))
		for i, rule := range batch {
			details[i] = rule.toAddDetails()
		}
		_, err := r.data.network.AddNetworkSecurityGroupSecurityRules(ctx, core.AddNetworkSecurityGroupSecurityRulesRequest{
			NetworkSecurityGroupId:                      common.String(nsgID),
			AddNetworkSecurityGroupSecurityRulesDetails: core.AddNetworkSecurityGroupSecurityRulesDetails{SecurityRules: details},
		})
		if err != nil {
			diags.AddError("Unable to add NSG rules", err.Error())
			return diags
		}
	}

	for _, batch := range chunks(c.Update, maxRulesPerCall) {
		details := make([]core.UpdateSecurityRuleDetails, len(batch))
		for i, l := range batch {
			details[i] = l.Rule.toUpdateDetails(l.ID)
		}
		_, err := r.data.network.UpdateNetworkSecurityGroupSecurityRules(ctx, core.UpdateNetworkSecurityGroupSecurityRulesRequest{
			NetworkSecurityGroupId:                         common.String(nsgID),
			UpdateNetworkSecurityGroupSecurityRulesDetails: core.UpdateNetworkSecurityGroupSecurityRulesDetails{SecurityRules: details},
		})
		if err != nil {
			diags.AddError("Unable to update NSG rules", err.Error())
			return diags
		}
	}

	for _, batch := range chunks(c.Remove, maxRulesPerCall) {
		_, err := r.data.network.RemoveNetworkSecurityGroupSecurityRules(ctx, core.RemoveNetworkSecurityGroupSecurityRulesRequest{
			NetworkSecurityGroupId:                         common.String(nsgID),
			RemoveNetworkSecurityGroupSecurityRulesDetails: core.RemoveNetworkSecurityGroupSecurityRulesDetails{SecurityRuleIds: batch},
		})
		if err != nil {
			diags.AddError("Unable to remove NSG rules", err.Error())
			return diags
		}
	}

	return diags
}

func (r *NSGResource) listRules(ctx context.Context, nsgID string) ([]liveRule, error) {
	var out []liveRule
	req := core.ListNetworkSecurityGroupSecurityRulesRequest{NetworkSecurityGroupId: common.String(nsgID)}
	for {
		page, err := r.data.network.ListNetworkSecurityGroupSecurityRules(ctx, req)
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

func (r *NSGResource) waitForState(ctx context.Context, nsgID string, target core.NetworkSecurityGroupLifecycleStateEnum) error {
	deadline := time.Now().Add(nsgWaitTimeout)
	for {
		got, err := r.data.network.GetNetworkSecurityGroup(ctx, core.GetNetworkSecurityGroupRequest{
			NetworkSecurityGroupId: common.String(nsgID),
		})
		switch {
		case isNotFound(err) && target == core.NetworkSecurityGroupLifecycleStateTerminated:
			return nil
		case err != nil:
			return err
		case got.LifecycleState == target:
			return nil
		case time.Now().After(deadline):
			return fmt.Errorf("NSG %s is still %s after %s, expected %s", nsgID, got.LifecycleState, nsgWaitTimeout, target)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// desiredRules converts the planned rules set. Values are always known at apply time.
func desiredRules(ctx context.Context, set types.Set) ([]nsgRule, diag.Diagnostics) {
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
		if err != nil {
			diags.AddAttributeError(path.Root("rules"), "Invalid NSG rule", err.Error())
			continue
		}
		rules = append(rules, rule)
	}
	return rules, diags
}

func freeformTags(ctx context.Context, m types.Map) (map[string]string, diag.Diagnostics) {
	if m.IsNull() || m.IsUnknown() {
		return nil, nil
	}
	tags := map[string]string{}
	diags := m.ElementsAs(ctx, &tags, false)
	return tags, diags
}

func isNotFound(err error) bool {
	se, ok := common.IsServiceError(err)
	return ok && se.GetHTTPStatusCode() == 404
}

func isGone(s core.NetworkSecurityGroupLifecycleStateEnum) bool {
	return s == core.NetworkSecurityGroupLifecycleStateTerminating || s == core.NetworkSecurityGroupLifecycleStateTerminated
}
