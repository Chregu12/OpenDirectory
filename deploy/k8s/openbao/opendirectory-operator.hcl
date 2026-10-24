path "secret/data/opendirectory/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/metadata/opendirectory/*" {
  capabilities = ["read", "list", "delete"]
}

path "sys/health" {
  capabilities = ["read"]
}
