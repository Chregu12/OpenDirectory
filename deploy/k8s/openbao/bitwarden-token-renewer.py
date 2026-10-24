#!/usr/bin/env python3
"""Refresh the narrowly-scoped plugin token using Kubernetes auth."""

import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path


ADDRESS = "https://openbao-active.openbao.svc.cluster.local:8200"
ROLE = "openbao-bitwarden-token-renewer"
JWT_PATH = Path("/var/run/openbao-token/token")
CA_PATH = "/var/run/openbao-ca/homelab-ca.crt"
TLS_CONTEXT = ssl.create_default_context(cafile=CA_PATH)


def request(path, token=None, payload=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request_object = urllib.request.Request(
        f"{ADDRESS}/v1/{path}", data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request_object, context=TLS_CONTEXT, timeout=15) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        # Do not print response bodies: they may contain credentials or token data.
        raise RuntimeError(f"OpenBao request failed with HTTP {error.code} at {path}") from None
    return json.loads(raw) if raw else {}


try:
    login = request(
        "auth/kubernetes/login",
        payload={"role": ROLE, "jwt": JWT_PATH.read_text().strip()},
    )
    auth_token = login["auth"]["client_token"]
    issued_token = request("auth/token/create/bitwarden-sync", token=auth_token)
    request(
        "bitwarden/config",
        token=auth_token,
        payload={"bao_token": issued_token["auth"]["client_token"]},
    )
except Exception as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)

print("Updated the OpenBao-to-Vaultwarden sync token.")
