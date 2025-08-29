terraform {
  required_providers {
    xai = {
      source = "xerosec/xai"
    }
  }
}

provider "xai" {
  admin_api_key = var.xai_admin_api_key
  team_id       = var.xai_team_id
  # base_url    = "https://management-api.x.ai"  # Optional, defaults to this
}

variable "xai_admin_api_key" {
  description = "xAI Admin API Key"
  type        = string
  sensitive   = true
}

variable "xai_team_id" {
  description = "xAI Team ID"
  type        = string
}
