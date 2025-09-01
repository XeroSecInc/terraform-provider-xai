// Copyright (c) XeroSec, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
)

func TestAccAPIKeysDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config:            testAccAPIKeysDataSourceConfig,
				ConfigStateChecks: []statecheck.StateCheck{
					// Just check that the data source can be read without errors
					// We don't validate the exact contents since it depends on account state
				},
			},
		},
	})
}

const testAccAPIKeysDataSourceConfig = `
provider "xai" {
  # Uses XAI_ADMIN_API_KEY environment variable
}

data "xai_api_keys" "test" {}
`
