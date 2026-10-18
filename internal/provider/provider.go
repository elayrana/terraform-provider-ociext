// Copyright IBM Corp. 2021, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const (
	authAPIKey            = "ApiKey"
	authInstancePrincipal = "InstancePrincipal"

	// defaultMaxRulesPerNSG is the OCI service limit (ingress plus egress).
	defaultMaxRulesPerNSG = 120
)

// Ensure OCIExtProvider satisfies various provider interfaces.
var _ provider.Provider = &OCIExtProvider{}

// OCIExtProvider defines the provider implementation.
type OCIExtProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// OCIExtProviderModel describes the provider data model.
type OCIExtProviderModel struct {
	Auth              types.String `tfsdk:"auth"`
	ConfigFilePath    types.String `tfsdk:"config_file_path"`
	ConfigFileProfile types.String `tfsdk:"config_file_profile"`
	Region            types.String `tfsdk:"region"`
	MaxRulesPerNSG    types.Int64  `tfsdk:"max_rules_per_nsg"`
}

// providerData is handed to every resource on Configure.
type providerData struct {
	network        core.VirtualNetworkClient
	maxRulesPerNSG int
}

func (p *OCIExtProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ociext"
	resp.Version = p.version
}

func (p *OCIExtProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Extra resources for Oracle Cloud Infrastructure. Credentials are read from an OCI CLI config file or from the instance principal.",
		Attributes: map[string]schema.Attribute{
			"auth": schema.StringAttribute{
				MarkdownDescription: "Authentication method: `ApiKey` (default, uses the config file) or `InstancePrincipal`.",
				Optional:            true,
				Validators: []validator.String{
					stringvalidator.OneOf(authAPIKey, authInstancePrincipal),
				},
			},
			"config_file_path": schema.StringAttribute{
				MarkdownDescription: "Path to the OCI config file. Defaults to `~/.oci/config`.",
				Optional:            true,
			},
			"config_file_profile": schema.StringAttribute{
				MarkdownDescription: "Profile of the OCI config file to use. Defaults to `DEFAULT`. Missing values are not filled in from other profiles.",
				Optional:            true,
			},
			"region": schema.StringAttribute{
				MarkdownDescription: "OCI region, e.g. `eu-frankfurt-1`. Defaults to the region of the profile or of the instance.",
				Optional:            true,
			},
			"max_rules_per_nsg": schema.Int64Attribute{
				MarkdownDescription: fmt.Sprintf("Maximum rules per NSG checked at plan time. Defaults to the OCI limit of %d; raise it only if your tenancy has a higher limit.", defaultMaxRulesPerNSG),
				Optional:            true,
			},
		},
	}
}

func (p *OCIExtProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data OCIExtProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.Auth.IsUnknown() || data.ConfigFilePath.IsUnknown() || data.ConfigFileProfile.IsUnknown() ||
		data.Region.IsUnknown() || data.MaxRulesPerNSG.IsUnknown() {
		resp.Diagnostics.AddError("Unknown provider configuration",
			"The ociext provider configuration depends on values that are only known after apply. Use static values or variables.")
		return
	}

	var configProvider common.ConfigurationProvider
	var err error
	switch data.Auth.ValueString() {
	case authInstancePrincipal:
		configProvider, err = auth.InstancePrincipalConfigurationProvider()
	default:
		configProvider, err = apiKeyConfigProvider(data.ConfigFilePath.ValueString(), data.ConfigFileProfile.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to load OCI credentials", err.Error())
		return
	}

	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(configProvider)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create the OCI networking client", err.Error())
		return
	}
	if !data.Region.IsNull() {
		network.SetRegion(data.Region.ValueString())
	}
	retry := common.DefaultRetryPolicy()
	network.Configuration.RetryPolicy = &retry

	maxRules := defaultMaxRulesPerNSG
	if !data.MaxRulesPerNSG.IsNull() {
		maxRules = int(data.MaxRulesPerNSG.ValueInt64())
	}

	pd := &providerData{network: network, maxRulesPerNSG: maxRules}
	resp.DataSourceData = pd
	resp.ResourceData = pd
}

// apiKeyConfigProvider reads exactly one profile. Unlike common.CustomProfileConfigProvider
// it does not fill missing values from DEFAULT, so a personal profile can never
// silently end up using the credentials of another tenancy.
func apiKeyConfigProvider(path, profile string) (common.ConfigurationProvider, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".oci", "config")
	} else if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, rest)
	}
	if profile == "" {
		profile = "DEFAULT"
	}

	cp, err := common.ConfigurationProviderFromFileWithProfile(path, profile, "")
	if err != nil {
		return nil, err
	}
	if ok, err := common.IsConfigurationProviderValid(cp); !ok {
		return nil, fmt.Errorf("profile %q in %s is incomplete: %w", profile, path, err)
	}
	return cp, nil
}

func (p *OCIExtProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewNSGResource,
		NewNSGPeerRulesResource,
	}
}

func (p *OCIExtProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return nil
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &OCIExtProvider{
			version: version,
		}
	}
}
