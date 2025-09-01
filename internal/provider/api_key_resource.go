// Copyright (c) XeroSec, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Constants for error messages and API calls.
const (
	ClientErrorMsg       = "Client Error"
	ErrorCreatingRequest = "error creating request: %w"
	ErrorMakingRequest   = "error making request: %w"
	AuthorizationHeader  = "Authorization"
	BearerPrefix         = "Bearer "
	APIRequestFailedMsg  = "API request failed with status %d"
	ContentTypeHeader    = "Content-Type"
	ApplicationJSONType  = "application/json"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &APIKeyResource{}
var _ resource.ResourceWithImportState = &APIKeyResource{}

func NewAPIKeyResource() resource.Resource {
	return &APIKeyResource{}
}

// APIKeyResource defines the resource implementation.
type APIKeyResource struct {
	client *XAIClient
}

// APIKeyResourceModel describes the resource data model.
type APIKeyResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	ACLs           types.List   `tfsdk:"acls"`
	QPS            types.Int64  `tfsdk:"qps"`
	QPM            types.Int64  `tfsdk:"qpm"`
	TPM            types.String `tfsdk:"tpm"`
	Disabled       types.Bool   `tfsdk:"disabled"`
	APIKey         types.String `tfsdk:"api_key"`
	RedactedAPIKey types.String `tfsdk:"redacted_api_key"`
	UserID         types.String `tfsdk:"user_id"`
	TeamID         types.String `tfsdk:"team_id"`
	CreateTime     types.String `tfsdk:"create_time"`
	ModifyTime     types.String `tfsdk:"modify_time"`
}

// APIKeyRequest represents the request structure for creating an API key.
type APIKeyRequest struct {
	Name string   `json:"name"`
	ACLs []string `json:"acls"`
	QPS  *int64   `json:"qps,omitempty"`
	QPM  *int64   `json:"qpm,omitempty"`
	TPM  *string  `json:"tpm,omitempty"`
}

// APIKeyResponse represents the response structure from xAI API.
type APIKeyResponse struct {
	RedactedAPIKey string   `json:"redactedApiKey"`
	APIKey         string   `json:"apiKey,omitempty"`
	UserID         string   `json:"userId"`
	Name           string   `json:"name"`
	CreateTime     string   `json:"createTime"`
	ModifyTime     string   `json:"modifyTime"`
	TeamID         string   `json:"teamId"`
	APIKeyID       string   `json:"apiKeyId"`
	Disabled       bool     `json:"disabled"`
	QPS            *int64   `json:"qps,omitempty"`
	QPM            *int64   `json:"qpm,omitempty"`
	TPM            *string  `json:"tpm,omitempty"`
	ACLStrings     []string `json:"acl_strings"`
}

func (r *APIKeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_key"
}

func (r *APIKeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "xAI API Key resource",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "API key identifier",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Human-readable name for the API key",
				Required:            true,
			},
			"acls": schema.ListAttribute{
				MarkdownDescription: "Access control list for the API key. Use 'api-key:endpoint:*' and 'api-key:model:*' for full access.",
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				Default:             listdefault.StaticValue(types.ListValueMust(types.StringType, []attr.Value{})),
			},
			"qps": schema.Int64Attribute{
				MarkdownDescription: "Queries per second limit",
				Optional:            true,
			},
			"qpm": schema.Int64Attribute{
				MarkdownDescription: "Queries per minute limit",
				Optional:            true,
			},
			"tpm": schema.StringAttribute{
				MarkdownDescription: "Tokens per minute limit",
				Optional:            true,
			},
			"disabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the API key is disabled",
				Optional:            true,
				Computed:            true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "The full API key (only available on creation)",
				Computed:            true,
				Sensitive:           true,
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
		},
	}
}

func (r *APIKeyResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*XAIClient)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *XAIClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

func (r *APIKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data APIKeyResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Convert ACLs from Terraform list to Go slice
	var acls []string
	if !data.ACLs.IsNull() && !data.ACLs.IsUnknown() {
		aclElements := make([]types.String, 0, len(data.ACLs.Elements()))
		resp.Diagnostics.Append(data.ACLs.ElementsAs(ctx, &aclElements, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		for _, acl := range aclElements {
			acls = append(acls, acl.ValueString())
		}
	}

	// Create API request
	apiRequest := APIKeyRequest{
		Name: data.Name.ValueString(),
		ACLs: acls,
	}

	if !data.QPS.IsNull() {
		qps := data.QPS.ValueInt64()
		apiRequest.QPS = &qps
	}

	if !data.QPM.IsNull() {
		qpm := data.QPM.ValueInt64()
		apiRequest.QPM = &qpm
	}

	if !data.TPM.IsNull() {
		tpm := data.TPM.ValueString()
		apiRequest.TPM = &tpm
	}

	// Make API call to create the API key
	apiKeyResp, err := r.createAPIKey(ctx, apiRequest)
	if err != nil {
		resp.Diagnostics.AddError(ClientErrorMsg, fmt.Sprintf("Unable to create API key, got error: %s", err))
		return
	}

	// Map response to resource model
	data.ID = types.StringValue(apiKeyResp.APIKeyID)
	data.Name = types.StringValue(apiKeyResp.Name)
	data.APIKey = types.StringValue(apiKeyResp.APIKey)
	data.RedactedAPIKey = types.StringValue(apiKeyResp.RedactedAPIKey)
	data.UserID = types.StringValue(apiKeyResp.UserID)
	data.TeamID = types.StringValue(apiKeyResp.TeamID)
	data.CreateTime = types.StringValue(apiKeyResp.CreateTime)
	data.ModifyTime = types.StringValue(apiKeyResp.ModifyTime)
	data.Disabled = types.BoolValue(apiKeyResp.Disabled)

	// Convert ACLs back to Terraform list - only if API returns ACLs
	if len(apiKeyResp.ACLStrings) > 0 {
		aclValues := make([]attr.Value, len(apiKeyResp.ACLStrings))
		for i, acl := range apiKeyResp.ACLStrings {
			aclValues[i] = types.StringValue(acl)
		}
		data.ACLs = types.ListValueMust(types.StringType, aclValues)
	}
	// If API doesn't return ACLs, keep the ones from plan (don't modify data.ACLs)

	if apiKeyResp.QPS != nil {
		data.QPS = types.Int64Value(*apiKeyResp.QPS)
	} else {
		data.QPS = types.Int64Null()
	}

	if apiKeyResp.QPM != nil {
		data.QPM = types.Int64Value(*apiKeyResp.QPM)
	} else {
		data.QPM = types.Int64Null()
	}

	if apiKeyResp.TPM != nil {
		data.TPM = types.StringValue(*apiKeyResp.TPM)
	} else {
		data.TPM = types.StringNull()
	}

	// Write logs using the tflog package
	tflog.Trace(ctx, "created an API key resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data APIKeyResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Get the API key details from xAI API
	apiKeyResp, err := r.getAPIKey(ctx, data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(ClientErrorMsg, fmt.Sprintf("Unable to read API key, got error: %s", err))
		return
	}

	// Update the model with the latest data
	data.Name = types.StringValue(apiKeyResp.Name)
	data.RedactedAPIKey = types.StringValue(apiKeyResp.RedactedAPIKey)
	data.UserID = types.StringValue(apiKeyResp.UserID)
	data.TeamID = types.StringValue(apiKeyResp.TeamID)
	data.ModifyTime = types.StringValue(apiKeyResp.ModifyTime)
	data.Disabled = types.BoolValue(apiKeyResp.Disabled)

	// Convert ACLs back to Terraform list - only if API returns ACLs
	if len(apiKeyResp.ACLStrings) > 0 {
		aclValues := make([]attr.Value, len(apiKeyResp.ACLStrings))
		for i, acl := range apiKeyResp.ACLStrings {
			aclValues[i] = types.StringValue(acl)
		}
		data.ACLs = types.ListValueMust(types.StringType, aclValues)
	}
	// If API doesn't return ACLs, keep the ones from state/plan (don't modify data.ACLs)

	if apiKeyResp.QPS != nil {
		data.QPS = types.Int64Value(*apiKeyResp.QPS)
	} else {
		data.QPS = types.Int64Null()
	}

	if apiKeyResp.QPM != nil {
		data.QPM = types.Int64Value(*apiKeyResp.QPM)
	} else {
		data.QPM = types.Int64Null()
	}

	if apiKeyResp.TPM != nil {
		data.TPM = types.StringValue(*apiKeyResp.TPM)
	} else {
		data.TPM = types.StringNull()
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data APIKeyResourceModel
	var state APIKeyResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read current state to get the ID and other computed values
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert ACLs from Terraform list to Go slice
	var acls []string
	if !data.ACLs.IsNull() && !data.ACLs.IsUnknown() {
		aclElements := make([]types.String, 0, len(data.ACLs.Elements()))
		resp.Diagnostics.Append(data.ACLs.ElementsAs(ctx, &aclElements, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		for _, aclElement := range aclElements {
			acls = append(acls, aclElement.ValueString())
		}
	}

	// Build the update request - need to determine which fields changed
	var fieldMaskParts []string

	// Check which fields have changed and build the field mask
	if !data.Name.Equal(state.Name) {
		fieldMaskParts = append(fieldMaskParts, "name")
	}
	if !data.QPS.Equal(state.QPS) {
		fieldMaskParts = append(fieldMaskParts, "qps")
	}
	if !data.QPM.Equal(state.QPM) {
		fieldMaskParts = append(fieldMaskParts, "qpm")
	}
	if !data.TPM.Equal(state.TPM) {
		fieldMaskParts = append(fieldMaskParts, "tpm")
	}
	if !data.ACLs.Equal(state.ACLs) {
		fieldMaskParts = append(fieldMaskParts, "aclStrings")
	}

	if len(fieldMaskParts) == 0 {
		// No changes detected, just return current state
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}

	fieldMask := strings.Join(fieldMaskParts, ",")

	// Update the API key
	updatedAPIKey, err := r.updateAPIKey(ctx, state.ID.ValueString(), data.Name.ValueString(), acls, int(data.QPS.ValueInt64()), int(data.QPM.ValueInt64()), data.TPM.ValueString(), fieldMask)
	if err != nil {
		resp.Diagnostics.AddError(ClientErrorMsg, fmt.Sprintf("Unable to update API key, got error: %s", err))
		return
	}

	// Convert updated API key response to Terraform data
	data.ID = types.StringValue(updatedAPIKey.APIKeyID)
	data.RedactedAPIKey = types.StringValue(updatedAPIKey.RedactedAPIKey)
	data.UserID = types.StringValue(updatedAPIKey.UserID)
	data.TeamID = types.StringValue(updatedAPIKey.TeamID)
	data.CreateTime = types.StringValue(updatedAPIKey.CreateTime)
	data.ModifyTime = types.StringValue(updatedAPIKey.ModifyTime)
	data.Disabled = types.BoolValue(updatedAPIKey.Disabled)

	// Set QPS, QPM, TPM - handle nil values
	if updatedAPIKey.QPS != nil {
		data.QPS = types.Int64Value(*updatedAPIKey.QPS)
	} else {
		data.QPS = types.Int64Null()
	}

	if updatedAPIKey.QPM != nil {
		data.QPM = types.Int64Value(*updatedAPIKey.QPM)
	} else {
		data.QPM = types.Int64Null()
	}

	if updatedAPIKey.TPM != nil {
		data.TPM = types.StringValue(*updatedAPIKey.TPM)
	} else {
		data.TPM = types.StringNull()
	}

	// Preserve ACLs as planned since API may not return them
	if len(updatedAPIKey.ACLStrings) > 0 {
		aclList, diags := types.ListValueFrom(ctx, types.StringType, updatedAPIKey.ACLStrings)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.ACLs = aclList
	}
	// If API didn't return ACLs, preserve what was planned
	// (Keep the planned ACLs since API doesn't always echo them back)

	// Note: APIKey is not returned in update responses, so we don't update it
	data.APIKey = state.APIKey // Preserve original API key value

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *APIKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data APIKeyResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the API key
	err := r.deleteAPIKey(ctx, data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(ClientErrorMsg, fmt.Sprintf("Unable to delete API key, got error: %s", err))
		return
	}
}

func (r *APIKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Helper functions for API calls

func (r *APIKeyResource) createAPIKey(ctx context.Context, apiRequest APIKeyRequest) (*APIKeyResponse, error) {
	url := fmt.Sprintf("%s/auth/teams/%s/api-keys", r.client.BaseURL, r.client.TeamID)

	jsonData, err := json.Marshal(apiRequest)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf(ErrorCreatingRequest, err)
	}

	req.Header.Set(ContentTypeHeader, ApplicationJSONType)
	req.Header.Set(AuthorizationHeader, BearerPrefix+r.client.AdminAPIKey)

	resp, err := r.client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrorMakingRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(APIRequestFailedMsg, resp.StatusCode)
	}

	var apiKeyResp APIKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiKeyResp); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &apiKeyResp, nil
}

func (r *APIKeyResource) getAPIKey(ctx context.Context, apiKeyID string) (*APIKeyResponse, error) {
	// Note: The xAI API doesn't seem to have a direct "get single API key" endpoint
	// We would need to list all API keys and find the one we want
	// This is a simplified implementation
	url := fmt.Sprintf("%s/auth/teams/%s/api-keys", r.client.BaseURL, r.client.TeamID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrorCreatingRequest, err)
	}

	req.Header.Set(AuthorizationHeader, BearerPrefix+r.client.AdminAPIKey)

	resp, err := r.client.HTTPClient.Do(req)
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

	// Find the API key with matching ID
	for _, apiKey := range listResp.APIKeys {
		if apiKey.APIKeyID == apiKeyID {
			return &apiKey, nil
		}
	}

	return nil, fmt.Errorf("API key with ID %s not found", apiKeyID)
}

func (r *APIKeyResource) updateAPIKey(ctx context.Context, apiKeyID, name string, acls []string, qps, qpm int, tpm, fieldMask string) (*APIKeyResponse, error) {
	url := fmt.Sprintf("%s/auth/api-keys/%s", r.client.BaseURL, apiKeyID)

	// According to X.AI API docs, the request should have nested apiKey structure
	apiKeyData := map[string]interface{}{}

	// Only add fields that are in the field mask
	if strings.Contains(fieldMask, "name") {
		apiKeyData["name"] = name
	}
	if strings.Contains(fieldMask, "qps") {
		apiKeyData["qps"] = qps
	}
	if strings.Contains(fieldMask, "qpm") {
		apiKeyData["qpm"] = qpm
	}
	if strings.Contains(fieldMask, "tpm") {
		apiKeyData["tpm"] = tpm
	}
	if strings.Contains(fieldMask, "aclStrings") {
		apiKeyData["aclStrings"] = acls
	}

	updateReq := map[string]interface{}{
		"apiKey":    apiKeyData,
		"fieldMask": fieldMask,
	}

	jsonData, err := json.Marshal(updateReq)
	if err != nil {
		return nil, fmt.Errorf("error marshaling update request: %w", err)
	}

	tflog.Debug(ctx, "Making API update request", map[string]interface{}{
		"url":         url,
		"method":      "PUT",
		"fieldMask":   fieldMask,
		"requestBody": string(jsonData),
	})

	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf(ErrorCreatingRequest, err)
	}

	req.Header.Set(ContentTypeHeader, ApplicationJSONType)
	req.Header.Set(AuthorizationHeader, BearerPrefix+r.client.AdminAPIKey)

	resp, err := r.client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrorMakingRequest, err)
	}
	defer resp.Body.Close()

	// Read the response body for better error debugging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err == nil {
		tflog.Debug(ctx, "API update response", map[string]interface{}{
			"statusCode": resp.StatusCode,
			"body":       string(bodyBytes),
		})
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Reset body for JSON decoding if successful
	var apiKeyResp APIKeyResponse
	if err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&apiKeyResp); err != nil {
		return nil, fmt.Errorf("error decoding update response: %w", err)
	}

	return &apiKeyResp, nil
}

func (r *APIKeyResource) deleteAPIKey(ctx context.Context, apiKeyID string) error {
	url := fmt.Sprintf("%s/auth/api-keys/%s", r.client.BaseURL, apiKeyID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf(ErrorCreatingRequest, err)
	}

	req.Header.Set(AuthorizationHeader, BearerPrefix+r.client.AdminAPIKey)

	resp, err := r.client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf(ErrorMakingRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(APIRequestFailedMsg, resp.StatusCode)
	}

	return nil
}
