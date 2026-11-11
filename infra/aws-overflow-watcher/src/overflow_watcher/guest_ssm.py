# SPDX-License-Identifier: MPL-2.0
"""Read and delete one SSM parameter from the guest with stdlib only.

Stock Ubuntu images ship python3 but not the aws CLI. Credentials and region
come from IMDSv2; requests are SigV4-signed JSON calls to the SSM endpoint.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import sys
import urllib.request
from dataclasses import dataclass

IMDS = "http://169.254.169.254"
SERVICE = "ssm"


@dataclass(frozen=True)
class Credentials:
    access_key: str
    secret_key: str
    token: str


def _imds_open(path: str, token: str | None = None, method: str = "GET") -> str:
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "300"} if token is None else {"X-aws-ec2-metadata-token": token}
    request = urllib.request.Request(IMDS + path, method=method, headers=headers)
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read().decode("utf-8")


def instance_identity() -> tuple[Credentials, str]:
    token = _imds_open("/latest/api/token", method="PUT")
    region = _imds_open("/latest/meta-data/placement/region", token).strip()
    role = _imds_open("/latest/meta-data/iam/security-credentials/", token).strip().splitlines()[0]
    doc = json.loads(_imds_open(f"/latest/meta-data/iam/security-credentials/{role}", token))
    return Credentials(doc["AccessKeyId"], doc["SecretAccessKey"], doc["Token"]), region


def _hmac(key: bytes, text: str) -> bytes:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()


def signed_request(target: str, body: bytes, creds: Credentials, region: str, now: datetime.datetime) -> urllib.request.Request:
    """Build one SigV4-signed POST for the SSM JSON protocol."""
    host = f"{SERVICE}.{region}.amazonaws.com"
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = amz_date[:8]
    headers = {
        "content-type": "application/x-amz-json-1.1",
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-security-token": creds.token,
        "x-amz-target": f"AmazonSSM.{target}",
    }
    names = sorted(headers)
    canonical = "\n".join(
        [
            "POST",
            "/",
            "",
            "".join(f"{name}:{headers[name]}\n" for name in names),
            ";".join(names),
            hashlib.sha256(body).hexdigest(),
        ]
    )
    scope = f"{day}/{region}/{SERVICE}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(("AWS4" + creds.secret_key).encode("utf-8"), day), region), SERVICE), "aws4_request")
    signature = hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={creds.access_key}/{scope}, SignedHeaders={';'.join(names)}, Signature={signature}"
    )
    return urllib.request.Request(f"https://{host}/", data=body, method="POST", headers=headers)


def call(target: str, payload: dict) -> dict:
    creds, region = instance_identity()
    body = json.dumps(payload).encode("utf-8")
    now = datetime.datetime.now(datetime.timezone.utc)
    with urllib.request.urlopen(signed_request(target, body, creds, region, now), timeout=15) as response:
        return json.loads(response.read().decode("utf-8") or "{}")


def main(argv: list[str]) -> int:
    """`get NAME` writes the decrypted value to stdout; `delete NAME` removes it."""
    if len(argv) != 3 or argv[1] not in {"get", "delete"}:
        print("usage: guest_ssm get|delete NAME", file=sys.stderr)
        return 2
    action, name = argv[1], argv[2]
    try:
        if action == "get":
            value = call("GetParameter", {"Name": name, "WithDecryption": True})["Parameter"]["Value"]
            if not isinstance(value, str) or not value:
                raise ValueError("empty parameter")
            sys.stdout.write(value)
        else:
            call("DeleteParameter", {"Name": name})
    except Exception as exc:  # never print the value; the caller fails closed
        print(f"overflow-ssm {action} failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
