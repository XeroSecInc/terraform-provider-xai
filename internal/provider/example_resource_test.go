// Copyright (c) XeroSec, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccAPIKeyResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccAPIKeyResourceConfig("test-key"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"xai_api_key.test",
						tfjsonpath.New("name"),
						knownvalue.StringExact("test-key")),
				},
			},
			// ImportState testing
			{
				ResourceName:      "xai_api_key.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				Config: testAccAPIKeyResourceConfig("updated-test-key"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(
						"xai_api_key.test",
						tfjsonpath.New("name"),
						knownvalue.StringExact("updated-test-key")),
				},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccAPIKeyResourceConfig(name string) string {
	return fmt.Sprintf(`
resource "xai_api_key" "test" {
  name = %[1]q
}
`, name)
}
