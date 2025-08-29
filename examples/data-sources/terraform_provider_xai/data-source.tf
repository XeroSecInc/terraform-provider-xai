data "xai_api_keys" "example" {}

output "api_keys" {
  value = data.xai_api_keys.example.api_keys
}
