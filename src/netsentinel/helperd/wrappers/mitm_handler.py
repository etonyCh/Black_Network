import json
import os
import uuid
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

SHM_DIR = Path("/dev/shm")  # nosec B108


class NetSentinelMitmAddon:
    def __init__(self) -> None:
        key = os.environ.get("NETSENTINEL_DISPOSABLE_KEY")
        if not key:
            # Fallback for standalone / testing
            key = Fernet.generate_key().decode()
        self.fernet = Fernet(key.encode())

    def response(self, flow: Any) -> None:
        """
        Intercepts HTTP response, encrypts request/response body,
        and logs metadata to stdout.
        """
        try:
            req = flow.request
            resp = flow.response

            # Check if text is present
            req_body = req.text if req.text else ""
            resp_body = resp.text if resp.text else ""

            # Analysis of content for cleartext credentials / vulns
            alerts = []
            if "password=" in req_body or "passwd=" in req_body:
                alerts.append("Cleartext password payload detected in request!")

            # Store encrypted bodies in RAM-only /dev/shm
            payload_id = str(uuid.uuid4())
            payload_data = json.dumps(
                {
                    "request_headers": dict(req.headers),
                    "request_body": req_body,
                    "response_headers": dict(resp.headers),
                    "response_body": resp_body,
                }
            )

            encrypted_data = self.fernet.encrypt(payload_data.encode("utf-8"))
            file_path = SHM_DIR / f"netsentinel_decrypted_{payload_id}.enc"

            with file_path.open("wb") as f:
                f.write(encrypted_data)

            # Print metadata to stdout for the helper daemon to capture
            metadata = {
                "type": "intercept",
                "payload_id": payload_id,
                "url": req.pretty_url,
                "method": req.method,
                "status": resp.status_code,
                "size": len(resp_body),
                "alerts": alerts,
            }
            print(f"NETSENTINEL_MITM_JSON:{json.dumps(metadata)}")  # noqa: T201

        except Exception as e:
            # Print error so daemon logging can capture it
            print(f"NETSENTINEL_MITM_ERROR:Failed to process intercept: {e}")  # noqa: T201


addons = [NetSentinelMitmAddon()]
