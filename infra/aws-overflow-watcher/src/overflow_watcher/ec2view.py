# SPDX-License-Identifier: MPL-2.0
"""EC2 reads and RunInstances. Termination is not implemented here."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from overflow_watcher.types import (
    TAG_KEY,
    TAG_VALUE,
    AmbiguousLaunch,
    CapacityRefused,
    Ec2Uncertainty,
    InstanceView,
)

# A response with one of these codes did not create an instance.
_DEFINITIVE_NO_CREATE = frozenset(
    {
        "VcpuLimitExceeded",
        "InsufficientInstanceCapacity",
        "InstanceLimitExceeded",
        "MaxSpotInstanceCountExceeded",
        "InsufficientHostCapacity",
        "InsufficientCapacity",
        "InvalidParameterValue",
        "InvalidParameterCombination",
    }
)


class Ec2Views:
    def __init__(self, client: Any) -> None:
        self._client = client

    def describe_instances(self, ids: list[str]) -> dict[str, InstanceView]:
        if not ids:
            return {}
        try:
            response = self._client.describe_instances(InstanceIds=ids)
        except ClientError as exc:
            raise Ec2Uncertainty(exc.response["Error"]["Code"]) from exc
        found: dict[str, InstanceView] = {}
        for reservation in response.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                tags = {tag["Key"]: tag["Value"] for tag in inst.get("Tags", [])}
                found[inst["InstanceId"]] = InstanceView(
                    instance_id=inst["InstanceId"],
                    state=(inst.get("State") or {}).get("Name"),
                    has_tag=tags.get(TAG_KEY) == TAG_VALUE,
                    uncertain=False,
                )
        return {
            instance_id: found.get(
                instance_id, InstanceView(instance_id, None, False, True)
            )
            for instance_id in ids
        }

    def list_tagged_ids(self) -> list[str] | None:
        try:
            response = self._client.describe_instances(
                Filters=[
                    {"Name": f"tag:{TAG_KEY}", "Values": [TAG_VALUE]},
                    {"Name": "instance-state-name", "Values": ["pending", "running"]},
                ]
            )
        except ClientError:
            return None
        ids: list[str] = []
        for reservation in response.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                ids.append(inst["InstanceId"])
        return ids

    def index_count(self) -> int | None:
        return None

    def run_instances(self, token: str, params: dict[str, Any]) -> str:
        try:
            response = self._client.run_instances(ClientToken=token, **params)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in _DEFINITIVE_NO_CREATE or "Capacity" in code or "Vcpu" in code:
                raise CapacityRefused(code) from exc
            raise AmbiguousLaunch(code) from exc
        instances = response.get("Instances") or []
        if len(instances) != 1 or not instances[0].get("InstanceId"):
            raise AmbiguousLaunch("missing-instance-id")
        return str(instances[0]["InstanceId"])
