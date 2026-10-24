path "secret/data/opendirectory/runtime" {
  capabilities = ["read"]
}

path "secret/data/opendirectory/files" {
  capabilities = ["read"]
}

path "secret/data/opendirectory/harbor/pull" {
  capabilities = ["read"]
}

path "database/static-creds/opendirectory" {
  capabilities = ["read"]
}
