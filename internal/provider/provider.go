// Copyright (c) XeroSec, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure XAIProvider satisfies various provider interfaces.
var _ provider.Provider = &XAIProvider{}

// XAIProvider defines the provider implementation.
type XAIProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// XAIProviderModel describes the provider data model.
type XAIProviderModel struct {
	AdminAPIKey types.String `tfsdk:"admin_api_key"`
	TeamID      types.String `tfsdk:"team_id"`
	BaseURL     types.String `tfsdk:"base_url"`
}

// XAIClient contains the configuration for making API calls to xAI.
type XAIClient struct {
	AdminAPIKey string
	TeamID      string
	BaseURL     string
	HTTPClient  *http.Client
}

func (p *XAIProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "xai"
	resp.Version = p.version
}

func (p *XAIProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The xAI provider allows you to manage xAI API keys using an admin API key.",
		Attributes: map[string]schema.Attribute{
			"admin_api_key": schema.StringAttribute{
				MarkdownDescription: "xAI Admin API Key for authentication. Can also be provided via the XAI_ADMIN_API_KEY environment variable.",
				Optional:            true,
				Sensitive:           true,
			},
			"team_id": schema.StringAttribute{
				MarkdownDescription: "xAI Team ID. Can also be provided via the XAI_TEAM_ID environment variable.",
				Optional:            true,
			},
			"base_url": schema.StringAttribute{
				MarkdownDescription: "Base URL for xAI API. Defaults to https://api.x.ai.",
				Optional:            true,
			},
		},
	}
}

func (p *XAIProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data XAIProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Get values from environment variables if not set in configuration
	adminAPIKey := data.AdminAPIKey.ValueString()
	if adminAPIKey == "" {
		adminAPIKey = getEnvVar("XAI_ADMIN_API_KEY")
	}

	teamID := data.TeamID.ValueString()
	if teamID == "" {
		teamID = getEnvVar("XAI_TEAM_ID")
	}

	baseURL := data.BaseURL.ValueString()
	if baseURL == "" {
		baseURL = "https://management-api.x.ai"
	}

	// Validate required configuration
	if adminAPIKey == "" {
		resp.Diagnostics.AddError(
			"Missing Admin API Key",
			"The admin_api_key must be provided either in the provider configuration or via the XAI_ADMIN_API_KEY environment variable.",
		)
		return
	}

	if teamID == "" {
		resp.Diagnostics.AddError(
			"Missing Team ID",
			"The team_id must be provided either in the provider configuration or via the XAI_TEAM_ID environment variable.",
		)
		return
	}

	// Create xAI client
	client := &XAIClient{
		AdminAPIKey: adminAPIKey,
		TeamID:      teamID,
		BaseURL:     baseURL,
		HTTPClient:  http.DefaultClient,
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *XAIProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAPIKeyResource,
	}
}

func (p *XAIProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewAPIKeysDataSource,
	}
}

func (p *XAIProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{}
}

func (p *XAIProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

// getEnvVar is a helper function to get environment variables.
func getEnvVar(key string) string {
	return os.Getenv(key)
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &XAIProvider{
			version: version,
		}
	}
}
