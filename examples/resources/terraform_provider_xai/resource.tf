resource "xai_api_key" "example" {
  name = "my-api-key"
  acls = [
    "api-key:endpoint:*",
    "api-key:model:*"
  ]
  qps = 100
  qpm = 6000
  tpm = "100000"
}
