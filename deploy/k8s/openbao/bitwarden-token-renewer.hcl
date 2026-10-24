path "auth/token/create/bitwarden-sync" {
  capabilities = ["update"]
}

path "bitwarden/config" {
  capabilities = ["update"]
  allowed_parameters = {
    "bao_token" = ["*"]
  }
}
