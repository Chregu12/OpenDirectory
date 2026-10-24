#!/usr/bin/env python3
"""Blue/green rotation for one project-scoped Harbor pull robot."""

import base64
import datetime as dt
import json
import os
import secrets
import ssl
import string
import sys
import time
import urllib.error
import urllib.request


def required(name):
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"required environment variable {name} is missing")
    return value


def url_host(url):
    return url.split("/", 3)[2]


def request_json(url, method="GET", payload=None, headers=None, context=None):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        # Never include API response bodies; they may contain credential fields.
        raise RuntimeError(f"request to {url_host(url)} failed with HTTP {error.code}") from None


def openbao_headers(token, content_type=False):
    headers = {"X-Vault-Token": token}
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers


def harbor_headers(username, password, content_type=False):
    basic = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    headers = {"Authorization": f"Basic {basic}", "Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers


def openbao_login(address, role, context):
    with open("/var/run/secrets/openbao/token", "r", encoding="utf-8") as handle:
        jwt = handle.read().strip()
    _, result = request_json(
        f"{address}/v1/auth/kubernetes/login",
        method="POST",
        payload={"role": role, "jwt": jwt},
        headers={"Content-Type": "application/json"},
        context=context,
    )
    token = (result or {}).get("auth", {}).get("client_token")
    if not token:
        raise RuntimeError("OpenBao Kubernetes login did not return a token")
    return token


def read_pull_secret(address, path, token, context):
    _, response = request_json(
        f"{address}/v1/secret/data/{path}",
        headers=openbao_headers(token),
        context=context,
    )
    values = (response or {}).get("data", {}).get("data", {})
    if not values.get("robot_id") or not values.get("dockerconfigjson"):
        raise RuntimeError("OpenBao pull secret must contain robot_id and dockerconfigjson")
    docker_config = values["dockerconfigjson"]
    if isinstance(docker_config, str):
        docker_config = json.loads(docker_config)
    return values, docker_config


def write_pull_secret(address, path, token, values, context):
    request_json(
        f"{address}/v1/secret/data/{path}",
        method="POST",
        payload={"data": values},
        headers=openbao_headers(token, content_type=True),
        context=context,
    )


def harbor_request(base, path, username, password, method="GET", payload=None, context=None):
    return request_json(
        f"{base}/api/v2.0/{path.lstrip('/')}",
        method=method,
        payload=payload,
        headers=harbor_headers(username, password, content_type=payload is not None),
        context=context,
    )


def validate_old_robot(robot, project):
    if robot.get("level") != "project":
        raise RuntimeError("current Harbor robot is not project-scoped; refusing rotation")
    permissions = robot.get("permissions") or []
    if not permissions:
        raise RuntimeError("Harbor did not return robot permissions; refusing rotation")
    for permission in permissions:
        if permission.get("kind") != "project" or permission.get("namespace") != project:
            raise RuntimeError("current Harbor robot has access outside the target project")
        for access in permission.get("access") or []:
            if access.get("resource") != "repository" or access.get("action") != "pull":
                raise RuntimeError("current Harbor robot has permissions beyond repository pull")


def build_docker_config(registry, username, password, previous):
    config = dict(previous)
    auths = dict(config.get("auths") or {})
    auth = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    auths[registry] = {"username": username, "password": password, "auth": auth}
    config["auths"] = auths
    return json.dumps(config, separators=(",", ":"))


def wait_for_external_secret(namespace, registry, username, password, timeout_seconds):
    api_host = required("KUBERNETES_SERVICE_HOST")
    api_port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    with open(token_path, "r", encoding="utf-8") as handle:
        token = handle.read().strip()
    context = ssl.create_default_context(cafile=ca_path)
    url = f"https://{api_host}:{api_port}/api/v1/namespaces/{namespace}/secrets/harbor-opendirectory"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            _, secret = request_json(url, headers=headers, context=context)
            encoded = secret.get("data", {}).get(".dockerconfigjson")
            if encoded:
                config = json.loads(base64.b64decode(encoded).decode("utf-8"))
                entry = config.get("auths", {}).get(registry, {})
                if entry.get("username") == username and entry.get("password") == password:
                    return
        except RuntimeError as error:
            if "HTTP 404" not in str(error):
                raise
        time.sleep(5)
    raise RuntimeError("ESO did not publish the new Harbor pull credential before timeout")


def check_registry_login(registry, username, password, context):
    basic = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(f"https://{registry}/v2/", headers={"Authorization": f"Basic {basic}"})
    try:
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError(f"Harbor registry login returned HTTP {response.status}")
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Harbor registry login failed with HTTP {error.code}") from None


def main():
    bao_address = required("OPENBAO_ADDR").rstrip("/")
    bao_role = required("OPENBAO_ROLE")
    secret_path = required("OPENBAO_SECRET_PATH")
    harbor_address = required("HARBOR_API_URL").rstrip("/")
    registry = required("HARBOR_REGISTRY")
    project = required("HARBOR_PROJECT")
    namespace = os.environ.get("KUBERNETES_NAMESPACE", "opendirectory")
    api_username = required("HARBOR_API_USERNAME")
    api_password = required("HARBOR_API_PASSWORD")
    sync_timeout = int(os.environ.get("ESO_SYNC_TIMEOUT_SECONDS", "300"))
    bao_context = ssl.create_default_context(cafile=required("OPENBAO_CA_FILE"))
    harbor_context = ssl.create_default_context(cafile=os.environ.get("HARBOR_CA_FILE", required("OPENBAO_CA_FILE")))

    bao_token = openbao_login(bao_address, bao_role, bao_context)
    old_values, old_config = read_pull_secret(bao_address, secret_path, bao_token, bao_context)
    old_id = int(old_values["robot_id"])
    old_entry = old_config.get("auths", {}).get(registry, {})
    if not old_entry.get("username") or not old_entry.get("password"):
        raise RuntimeError("OpenBao docker config is missing Harbor username or password")

    old_robot = harbor_request(harbor_address, f"robots/{old_id}", api_username, api_password, context=harbor_context)[1]
    if not old_robot or int(old_robot.get("id", -1)) != old_id:
        raise RuntimeError("Harbor did not return the expected robot account")
    validate_old_robot(old_robot, project)

    suffix = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    _, new_robot = harbor_request(
        harbor_address,
        "robots",
        api_username,
        api_password,
        method="POST",
        payload={
            "name": f"opendirectory-pull-{suffix}",
            "description": "OpenDirectory pull robot, rotated by OpenBao automation",
            "level": "project",
            "duration": 90,
            "permissions": [{
                "kind": "project",
                "namespace": project,
                "access": [{"resource": "repository", "action": "pull"}],
            }],
        },
        context=harbor_context,
    )
    new_id = None
    try:
        new_id = int(new_robot["id"])
        new_username = new_robot["name"]
        new_password = new_robot["secret"]
        if not new_username or not new_password:
            raise RuntimeError("Harbor did not return the replacement robot credentials")
        new_config = build_docker_config(registry, new_username, new_password, old_config)
        new_values = {"robot_id": str(new_id), "dockerconfigjson": new_config}
        write_pull_secret(bao_address, secret_path, bao_token, new_values, bao_context)
        wait_for_external_secret(namespace, registry, new_username, new_password, sync_timeout)
        check_registry_login(registry, new_username, new_password, harbor_context)
    except Exception:
        rollback_ok = False
        try:
            write_pull_secret(bao_address, secret_path, bao_token, old_values, bao_context)
            wait_for_external_secret(namespace, registry, old_entry["username"], old_entry["password"], sync_timeout)
            rollback_ok = True
        except Exception:
            print("OpenBao/ESO rollback could not be verified; the temporary Harbor robot was left active.", file=sys.stderr)
        if rollback_ok and new_id is not None:
            try:
                harbor_request(harbor_address, f"robots/{new_id}", api_username, api_password, method="DELETE", context=harbor_context)
            except Exception:
                print("Rotation rollback left a temporary Harbor robot; remove it manually.", file=sys.stderr)
        raise

    try:
        harbor_request(harbor_address, f"robots/{old_id}", api_username, api_password, method="DELETE", context=harbor_context)
    except Exception:
        print("New pull robot is active, but the old robot could not be deleted; remove it manually.", file=sys.stderr)
        raise

    print(f"Harbor pull credential rotated successfully; current robot id is {new_id}.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Harbor robot rotation failed: {error}", file=sys.stderr)
        sys.exit(1)
