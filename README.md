# Terraform Provider for xAI

This Terraform provider allows you to manage xAI API keys using the xAI Admin API.

## Features

- **Resource**: `xai_api_key` - Create, read, update, and delete xAI API keys
- **Data Source**: `xai_api_keys` - List all API keys for a team

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.23
- xAI Admin API Key with appropriate permissions
- xAI Team ID

## Usage

### Provider Configuration

```hcl
terraform {
  required_providers {
    xai = {
      source = "xerosec/xai"
    }
  }
}

provider "xai" {
  admin_api_key = var.xai_admin_api_key  # Can also use XAI_ADMIN_API_KEY env var
  team_id       = var.xai_team_id        # Can also use XAI_TEAM_ID env var
}
```

### Creating an API Key

```hcl
resource "xai_api_key" "example" {
  name = "my-terraform-api-key"
  acls = [
    "api-key:endpoint:*",  # Access to all endpoints
    "api-key:model:*"      # Access to all models
  ]
  qps = 100       # Queries per second limit (optional)
  qpm = 6000      # Queries per minute limit (optional)
  tpm = "100000"  # Tokens per minute limit (optional)
}

# The API key value (only available on creation)
output "api_key" {
  value     = xai_api_key.example.api_key
  sensitive = true
}
```

### Listing API Keys

```hcl
data "xai_api_keys" "all" {}

output "api_keys" {
  value = data.xai_api_keys.all.api_keys
}
```

## Building The Provider

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the Go `install` command:

```shell
go install
```

## Adding Dependencies

This provider uses [Go modules](https://github.com/golang/go/wiki/Modules).
Please see the Go documentation for the most up to date information about using Go modules.

To add a new dependency `github.com/author/dependency` to your Terraform provider:

```shell
go get github.com/author/dependency
go mod tidy
```

Then commit the changes to `go.mod` and `go.sum`.

## Using the provider

Fill this in for each provider

## Developing the Provider

If you wish to work on the provider, you'll first need [Go](http://www.golang.org) installed on your machine (see [Requirements](#requirements) above).

To compile the provider, run `go install`. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.

To generate or update documentation, run `make generate`.

In order to run the full suite of Acceptance tests, run `make testacc`.

_Note:_ Acceptance tests create real resources.

```shell
make testacc
```
