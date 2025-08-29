// Copyright (c) XeroSec, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &APIKeysDataSource{}

func NewAPIKeysDataSource() datasource.DataSource {
	return &APIKeysDataSource{}
}

// APIKeysDataSource defines the data source implementation.
type APIKeysDataSource struct {
	client *XAIClient
}

// APIKeysDataSourceModel describes the data source data model.
type APIKeysDataSourceModel struct {
	APIKeys types.List   `tfsdk:"api_keys"`
	ID      types.String `tfsdk:"id"`
}

// APIKeyDataModel represents a single API key in the data source.
type APIKeyDataModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	RedactedAPIKey types.String `tfsdk:"redacted_api_key"`
	UserID         types.String `tfsdk:"user_id"`
	TeamID         types.String `tfsdk:"team_id"`
	CreateTime     types.String `tfsdk:"create_time"`
	ModifyTime     types.String `tfsdk:"modify_time"`
	Disabled       types.Bool   `tfsdk:"disabled"`
	QPS            types.Int64  `tfsdk:"qps"`
	QPM            types.Int64  `tfsdk:"qpm"`
	TPM            types.String `tfsdk:"tpm"`
	ACLs           types.List   `tfsdk:"acls"`
}

func (d *APIKeysDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_keys"
}

func (d *APIKeysDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "xAI API Keys data source",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Data source identifier",
				Computed:            true,
			},
			"api_keys": schema.ListNestedAttribute{
				MarkdownDescription: "List of API keys",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							MarkdownDescription: "API key identifier",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "Human-readable name for the API key",
							Computed:            true,
						},
						"redacted_api_key": schema.StringAttribute{
							MarkdownDescription: "The redacted API key",
							Computed:            true,
						},
						"user_id": schema.StringAttribute{
							MarkdownDescription: "ID of the user who created this API key",
							Computed:            true,
						},
						"team_id": schema.StringAttribute{
							MarkdownDescription: "ID of the team this API key belongs to",
							Computed:            true,
						},
						"create_time": schema.StringAttribute{
							MarkdownDescription: "Timestamp when the API key was created",
							Computed:            true,
						},
						"modify_time": schema.StringAttribute{
							MarkdownDescription: "Timestamp when the API key was last modified",
							Computed:            true,
						},
						"disabled": schema.BoolAttribute{
							MarkdownDescription: "Whether the API key is disabled",
							Computed:            true,
						},
						"qps": schema.Int64Attribute{
							MarkdownDescription: "Queries per second limit",
							Computed:            true,
						},
						"qpm": schema.Int64Attribute{
							MarkdownDescription: "Queries per minute limit",
							Computed:            true,
						},
						"tpm": schema.StringAttribute{
							MarkdownDescription: "Tokens per minute limit",
							Computed:            true,
						},
						"acls": schema.ListAttribute{
							MarkdownDescription: "Access control list for the API key",
							ElementType:         types.StringType,
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

func (d *APIKeysDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*XAIClient)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *XAIClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.client = client
}

func (d *APIKeysDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data APIKeysDataSourceModel

	// Read Terraform configuration data into the model
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Get API keys from xAI API
	apiKeys, err := d.listAPIKeys(ctx)
	if err != nil {
		resp.Diagnostics.AddError(ClientErrorMsg, fmt.Sprintf("Unable to read API keys, got error: %s", err))
		return
	}

	// Convert API response to Terraform data model
	apiKeyModels := make([]APIKeyDataModel, len(apiKeys))
	for i, apiKey := range apiKeys {
		// Convert ACLs to Terraform list
		aclValues := make([]attr.Value, len(apiKey.ACLStrings))
		for j, acl := range apiKey.ACLStrings {
			aclValues[j] = types.StringValue(acl)
		}

		apiKeyModels[i] = APIKeyDataModel{
			ID:             types.StringValue(apiKey.APIKeyID),
			Name:           types.StringValue(apiKey.Name),
			RedactedAPIKey: types.StringValue(apiKey.RedactedAPIKey),
			UserID:         types.StringValue(apiKey.UserID),
			TeamID:         types.StringValue(apiKey.TeamID),
			CreateTime:     types.StringValue(apiKey.CreateTime),
			ModifyTime:     types.StringValue(apiKey.ModifyTime),
			Disabled:       types.BoolValue(apiKey.Disabled),
			ACLs:           types.ListValueMust(types.StringType, aclValues),
		}

		if apiKey.QPS != nil {
			apiKeyModels[i].QPS = types.Int64Value(*apiKey.QPS)
		} else {
			apiKeyModels[i].QPS = types.Int64Null()
		}

		if apiKey.QPM != nil {
			apiKeyModels[i].QPM = types.Int64Value(*apiKey.QPM)
		} else {
			apiKeyModels[i].QPM = types.Int64Null()
		}

		if apiKey.TPM != nil {
			apiKeyModels[i].TPM = types.StringValue(*apiKey.TPM)
		} else {
			apiKeyModels[i].TPM = types.StringNull()
		}
	}

	// Convert to types.List
	apiKeysObjectType := types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"id":               types.StringType,
			"name":             types.StringType,
			"redacted_api_key": types.StringType,
			"user_id":          types.StringType,
			"team_id":          types.StringType,
			"create_time":      types.StringType,
			"modify_time":      types.StringType,
			"disabled":         types.BoolType,
			"qps":              types.Int64Type,
			"qpm":              types.Int64Type,
			"tpm":              types.StringType,
			"acls":             types.ListType{ElemType: types.StringType},
		},
	}

	apiKeysValues := make([]attr.Value, len(apiKeyModels))
	for i, apiKeyModel := range apiKeyModels {
		apiKeyValue, diags := types.ObjectValue(apiKeysObjectType.AttrTypes, map[string]attr.Value{
			"id":               apiKeyModel.ID,
			"name":             apiKeyModel.Name,
			"redacted_api_key": apiKeyModel.RedactedAPIKey,
			"user_id":          apiKeyModel.UserID,
			"team_id":          apiKeyModel.TeamID,
			"create_time":      apiKeyModel.CreateTime,
			"modify_time":      apiKeyModel.ModifyTime,
			"disabled":         apiKeyModel.Disabled,
			"qps":              apiKeyModel.QPS,
			"qpm":              apiKeyModel.QPM,
			"tpm":              apiKeyModel.TPM,
			"acls":             apiKeyModel.ACLs,
		})
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		apiKeysValues[i] = apiKeyValue
	}

	data.APIKeys = types.ListValueMust(apiKeysObjectType, apiKeysValues)
	data.ID = types.StringValue("api_keys")

	// Write logs using the tflog package
	tflog.Trace(ctx, "read an API keys data source")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Helper function to list API keys.
func (d *APIKeysDataSource) listAPIKeys(ctx context.Context) ([]APIKeyResponse, error) {
	url := fmt.Sprintf("%s/auth/teams/%s/api-keys", d.client.BaseURL, d.client.TeamID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrorCreatingRequest, err)
	}

	req.Header.Set(AuthorizationHeader, BearerPrefix+d.client.AdminAPIKey)

	resp, err := d.client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrorMakingRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(APIRequestFailedMsg, resp.StatusCode)
	}

	var listResp struct {
		APIKeys []APIKeyResponse `json:"apiKeys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return listResp.APIKeys, nil
}
