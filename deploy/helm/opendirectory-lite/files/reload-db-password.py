#!/usr/bin/env python3
import hashlib
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


namespace = os.environ["WATCH_NAMESPACE"]
secret_name = os.environ["DATABASE_SECRET_NAME"]
configmap_name = os.environ["RELOADER_CONFIGMAP_NAME"]
selector = os.environ["DEPLOYMENT_SELECTOR"]
service_account = "/var/run/secrets/kubernetes.io/serviceaccount"
token = open(os.path.join(service_account, "token"), encoding="utf-8").read().strip()
context = ssl.create_default_context(cafile=os.path.join(service_account, "ca.crt"))
api = "https://%s:%s" % (os.environ["KUBERNETES_SERVICE_HOST"], os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443"))


def request(path, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        api + path,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            "Content-Type": "application/merge-patch+json" if method == "PATCH" else "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError("Kubernetes API request failed with HTTP %d" % error.code) from None


prefix = "/api/v1/namespaces/%s" % namespace
secret = request(prefix + "/secrets/" + urllib.parse.quote(secret_name, safe=""))
encoded_password = secret.get("data", {}).get("postgres-app-initial-password")
if not encoded_password:
    raise RuntimeError("Database password key is missing")
current_hash = hashlib.sha256(encoded_password.encode()).hexdigest()
configmap = request(prefix + "/configmaps/" + urllib.parse.quote(configmap_name, safe=""))
if configmap.get("data", {}).get("passwordHash") == current_hash:
    print("Database password unchanged")
    raise SystemExit(0)

selector_query = urllib.parse.urlencode({"labelSelector": selector})
deployments = request("/apis/apps/v1/namespaces/%s/deployments?%s" % (namespace, selector_query))
restarted_at = datetime.now(timezone.utc).isoformat()
for deployment in deployments.get("items", []):
    name = deployment["metadata"]["name"]
    request(
        "/apis/apps/v1/namespaces/%s/deployments/%s" % (namespace, urllib.parse.quote(name, safe="")),
        method="PATCH",
        body={"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": restarted_at}}}}},
    )

request(
    prefix + "/configmaps/" + urllib.parse.quote(configmap_name, safe=""),
    method="PATCH",
    body={"data": {"passwordHash": current_hash}},
)
print("Restarted %d database workloads after credential refresh" % len(deployments.get("items", [])))
