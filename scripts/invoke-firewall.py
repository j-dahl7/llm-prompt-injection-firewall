"""Invoke only this checkout's Terraform-recorded API using AWS SigV4.

Credentials remain in memory/headers, never process arguments or printed output.
No resources, policies, or credentials are created by this client.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import botocore.session


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("API redirects are refused; no credentials were forwarded")


def validate_endpoint(endpoint, api_id, region):
    if not isinstance(api_id, str) or not re.fullmatch(r"[a-z0-9]{10}", api_id):
        raise ValueError("Invalid Terraform API identifier")
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", region):
        raise ValueError("Invalid Terraform AWS region")
    expected = f"https://{api_id}.execute-api.{region}.amazonaws.com/prompt"
    if endpoint != expected:
        raise ValueError("Endpoint must exactly match this deployment's HTTPS API and /prompt route")
    return expected


def invoke(endpoint, api_id, region, prompt, secret, credentials, opener=None):
    validate_endpoint(endpoint, api_id, region)
    if not isinstance(secret, str) or not 32 <= len(secret) <= 256 or not all(32 <= ord(ch) <= 126 for ch in secret):
        raise ValueError("This portable client requires a 32-256 character printable ASCII lab secret")
    if not isinstance(prompt, str) or not 1 <= len(prompt) <= 10000:
        raise ValueError("Prompt must contain 1-10000 characters")
    body = json.dumps({"prompt": prompt}, ensure_ascii=False).encode("utf-8")
    signed = AWSRequest(method="POST", url=endpoint, data=body, headers={
        "Content-Type": "application/json", "X-API-Key": secret
    })
    SigV4Auth(credentials, "execute-api", region).add_auth(signed)
    request = urllib.request.Request(endpoint, data=body, method="POST", headers=dict(signed.headers))
    transport = opener or urllib.request.build_opener(NoRedirect())
    try:
        response = transport.open(request, timeout=20)
    except urllib.error.HTTPError as error:
        if error.code not in (400, 401, 403, 413, 429):
            raise ValueError("API invocation failed; check the deployment and AWS permissions") from None
        response = error
    with response:
        payload = response.read(65537)
        if len(payload) > 65536:
            raise ValueError("API response exceeded its size limit")
        return response.status, json.loads(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(["terraform", f"-chdir={root / 'terraform'}", "output", "-json"],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError("Unable to read this checkout's Terraform outputs")
    outputs = json.loads(result.stdout)
    endpoint, api_id, region = (outputs[key]["value"] for key in ("api_endpoint", "api_id", "api_region"))
    validate_endpoint(endpoint, api_id, region)  # Before credential discovery.
    credentials = botocore.session.get_session().get_credentials()
    if credentials is None:
        raise ValueError("Configure an AWS profile permitted to invoke this exact API route")
    status, body = invoke(endpoint, api_id, region, args.prompt, os.environ.get("API_SHARED_SECRET"),
                          credentials.get_frozen_credentials())
    print(json.dumps({"http_status": status, "response": body}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Invocation failed. Check reviewed Terraform outputs, client input, AWS profile/permission and connectivity; no credentials were printed.") from None
