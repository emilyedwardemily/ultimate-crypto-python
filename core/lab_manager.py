import os
import json
import uuid
import time
import asyncio
import logging
import docker
from typing import Optional
from datetime import datetime, timedelta

client = docker.from_env() if os.getenv("DOCKER_HOST") else None

ACTIVE_LABS: dict[str, dict] = {}
LAB_TIMEOUT_MINUTES = int(os.getenv("CTF_LAB_TIMEOUT_MINUTES", "30"))
LAB_IMAGE = os.getenv("CTF_LAB_IMAGE", "kalilinux/rolling")
MAX_LABS_PER_USER = int(os.getenv("CTF_MAX_LABS_PER_USER", "3"))


def count_active_labs(operator_id: str) -> int:
    return sum(
        1 for lab in ACTIVE_LABS.values()
        if lab.get("operator_id") == operator_id and lab.get("status") != "terminated"
    )


async def provision_lab(
    operator_id: str,
    challenge_id: str,
    timeout_minutes: int = LAB_TIMEOUT_MINUTES,
) -> dict:
    if count_active_labs(operator_id) >= MAX_LABS_PER_USER:
        return {
            "error": f"Max {MAX_LABS_PER_USER} concurrent labs per user",
            "status": "rejected",
        }

    lab_id = f"lab-{uuid.uuid4().hex[:8]}"
    expiry = datetime.now() + timedelta(minutes=timeout_minutes)

    lab = {
        "lab_id": lab_id,
        "operator_id": operator_id,
        "challenge_id": challenge_id,
        "status": "provisioning",
        "created_at": datetime.now().isoformat(),
        "expires_at": expiry.isoformat(),
        "internal_ip": None,
        "connection_string": None,
    }

    try:
        if client and client.ping():
            container = client.containers.run(
                image=LAB_IMAGE,
                command="sleep infinity",
                detach=True,
                remove=True,
                network="uc-lab-network",
                labels={
                    "uc-lab-id": lab_id,
                    "uc-operator": operator_id,
                    "uc-challenge": challenge_id,
                },
                mem_limit="512m",
                cpu_period=100000,
                cpu_quota=50000,
            )
            container.reload()
            lab["internal_ip"] = container.attrs["NetworkSettings"]["IPAddress"]
            lab["status"] = "running"
            lab["container_id"] = container.id
        else:
            lab["status"] = "simulated"
            lab["internal_ip"] = "10.0.0.2"
            lab["connection_string"] = (
                f"ssh simulator@{lab['internal_ip']} -p 2222"
            )
    except docker.errors.DockerException as e:
        logging.warning(f"Docker unavailable, simulating lab: {e}")
        lab["status"] = "simulated"
        lab["connection_string"] = "docker not available — simulated environment"
    except Exception as e:
        lab["status"] = "failed"
        lab["error"] = str(e)
        return lab

    ACTIVE_LABS[lab_id] = lab
    return lab


async def terminate_lab(lab_id: str, operator_id: str) -> dict:
    lab = ACTIVE_LABS.get(lab_id)
    if not lab:
        return {"error": "Lab not found", "status": "not_found"}
    if lab["operator_id"] != operator_id:
        return {"error": "Unauthorized", "status": "unauthorized"}

    if lab.get("container_id") and client:
        try:
            container = client.containers.get(lab["container_id"])
            container.stop(timeout=5)
            container.remove(force=True)
        except docker.errors.NotFound:
            pass
        except Exception as e:
            logging.error(f"Failed to stop container {lab_id}: {e}")

    lab["status"] = "terminated"
    lab["terminated_at"] = datetime.now().isoformat()
    return {"status": "terminated", "lab_id": lab_id}


async def cleanup_expired_labs():
    now = datetime.now()
    expired = [
        lab_id
        for lab_id, lab in ACTIVE_LABS.items()
        if datetime.fromisoformat(lab["expires_at"]) < now
        and lab["status"] not in ("terminated",)
    ]
    for lab_id in expired:
        lab = ACTIVE_LABS[lab_id]
        await terminate_lab(lab_id, lab["operator_id"])
        logging.info(f"Auto-terminated expired lab: {lab_id}")


def list_labs(operator_id: Optional[str] = None) -> list[dict]:
    labs = ACTIVE_LABS.values()
    if operator_id:
        labs = [l for l in labs if l.get("operator_id") == operator_id]
    return sorted(labs, key=lambda l: l.get("created_at", ""), reverse=True)
