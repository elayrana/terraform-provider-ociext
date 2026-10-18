// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var (
	_ resource.Resource                   = &NSGPeerRulesResource{}
	_ resource.ResourceWithConfigure      = &NSGPeerRulesResource{}
	_ resource.ResourceWithImportState    = &NSGPeerRulesResource{}
	_ resource.ResourceWithValidateConfig = &NSGPeerRulesResource{}
	_ resource.ResourceWithModifyPlan     = &NSGPeerRulesResource{}
)

// maxForeignRulesShown caps the rules listed in the error of an NSG that already has peer rules.
const maxForeignRulesShown = 10

func NewNSGPeerRulesResource() resource.Resource {
	return &NSGPeerRulesResource{}
}

// NSGPeerRulesResource manages the rules of an NSG that point to an NSG.
// OCI has no entity for this group: it is all the rules of type NSG of one NSG,
// so its ID is the NSG OCID.
type NSGPeerRulesResource struct {
	data *providerData
}

type NSGPeerRulesResourceModel struct {
	ID    types.String `tfsdk:"id"`
	NsgID types.String `tfsdk:"nsg_id"`
	Rules types.Set    `tfsdk:"rules"`
}

func (r *NSGPeerRulesResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_nsg_peer_rules"
}

func (r *NSGPeerRulesResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Security rules of an NSG whose source or destination is an NSG, including the NSG itself. " +
			"They live apart from `ociext_nsg` so that NSGs can reference each other without a dependency cycle: " +
			"Terraform creates the NSGs first and then their peer rules. " +
			"The resource owns every rule of type NSG of the NSG: those rules created outside Terraform are removed on the next apply. " +
			"Use only one per NSG. Creating it fails if the NSG already has rules of type NSG that are not in the configuration; import them instead.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "OCID of the network security group, the same as `nsg_id`.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"nsg_id": schema.StringAttribute{
				MarkdownDescription: "OCID of the network security group the rules belong to.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"rules": rulesAttribute(true),
		},
	}
}

func (r *NSGPeerRulesResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.data = configuredData(req.ProviderData, &resp.Diagnostics)
}

func (r *NSGPeerRulesResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var rules types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("rules"), &rules)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(validateRules(ctx, rules, true)...)
}

func (r *NSGPeerRulesResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if r.data == nil {
		return
	}
	resp.Diagnostics.Append(checkRuleLimit(ctx, req.Plan, r.data.maxRulesPerNSG)...)
}

func (r *NSGPeerRulesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan NSGPeerRulesResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	nsgID := plan.NsgID.ValueString()

	desired, diags := desiredRules(ctx, plan.Rules, true)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	live, err := r.data.listRules(ctx, nsgID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read NSG rules", err.Error())
		return
	}
	live = inScope(live, true)

	// Peer rules that are not ours mean that another stack manages them or that
	// someone created them by hand. Taking them over silently would remove them.
	if foreign := foreignRules(desired, live); len(foreign) > 0 {
		shown := foreign
		if len(shown) > maxForeignRulesShown {
			shown = append(shown[:maxForeignRulesShown:maxForeignRulesShown], fmt.Sprintf("... and %d more", len(foreign)-maxForeignRulesShown))
		}
		resp.Diagnostics.AddAttributeError(path.Root("nsg_id"), "NSG already has peer rules",
			fmt.Sprintf("NSG %s already has %d rule(s) of type NSG that are not in this configuration:\n  %s\n\n"+
				"If they are yours, import them with: terraform import <address> %s\n"+
				"If another stack manages them, add these rules there: an NSG can only have one ociext_nsg_peer_rules.",
				nsgID, len(foreign), strings.Join(shown, "\n  "), nsgID))
		return
	}

	resp.Diagnostics.Append(r.data.applyRuleChanges(ctx, nsgID, diffRules(desired, live))...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = plan.NsgID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NSGPeerRulesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state NSGPeerRulesResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	nsgID := state.NsgID.ValueString()

	got, err := r.data.network.GetNetworkSecurityGroup(ctx, core.GetNetworkSecurityGroupRequest{
		NetworkSecurityGroupId: common.String(nsgID),
	})
	if isNotFound(err) || (err == nil && isGone(got.LifecycleState)) {
		tflog.Warn(ctx, "NSG no longer exists, removing its peer rules from state", map[string]any{"id": nsgID})
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read NSG", err.Error())
		return
	}

	live, err := r.data.listRules(ctx, nsgID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read NSG rules", err.Error())
		return
	}

	rules, diags := rulesToState(ctx, state.Rules, inScope(live, true), nsgID)
	resp.Diagnostics.Append(diags...)
	state.Rules = rules
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *NSGPeerRulesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan NSGPeerRulesResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	nsgID := plan.NsgID.ValueString()

	desired, diags := desiredRules(ctx, plan.Rules, true)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Diff against OCI, not against state, so the apply also fixes changes made since the last refresh.
	live, err := r.data.listRules(ctx, nsgID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read NSG rules", err.Error())
		return
	}
	resp.Diagnostics.Append(r.data.applyRuleChanges(ctx, nsgID, diffRules(desired, inScope(live, true)))...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NSGPeerRulesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state NSGPeerRulesResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	nsgID := state.NsgID.ValueString()

	live, err := r.data.listRules(ctx, nsgID)
	if isNotFound(err) {
		return // the NSG is gone and its rules with it
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read NSG rules", err.Error())
		return
	}
	resp.Diagnostics.Append(r.data.applyRuleChanges(ctx, nsgID, diffRules(nil, inScope(live, true)))...)
}

// ImportState takes the NSG OCID: the peer rules are all its rules of type NSG.
func (r *NSGPeerRulesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("nsg_id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("rules"), types.SetValueMust(nsgRuleObjectType, nil))...)
}
