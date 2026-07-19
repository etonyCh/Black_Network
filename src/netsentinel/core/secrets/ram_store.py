import contextlib
import uuid
from pathlib import Path

from cryptography.fernet import Fernet

SHM_DIR = Path("/dev/shm")  # nosec B108


class RamStore:
    def __init__(self) -> None:
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self.active_ids = set()  # type: set[str]

    def store(self, payload: str) -> str:
        """
        Encrypts payload using Fernet and saves it to a RAM-only file in /dev/shm.
        Returns a unique payload ID.
        """
        payload_id = str(uuid.uuid4())
        encrypted_data = self.fernet.encrypt(payload.encode("utf-8"))

        file_path = SHM_DIR / f"netsentinel_decrypted_{payload_id}.enc"

        # Write only in RAM
        with file_path.open("wb") as f:
            f.write(encrypted_data)

        self.active_ids.add(payload_id)
        return payload_id

    def retrieve(self, payload_id: str) -> str | None:
        """
        Retrieves and decrypts the payload matching payload_id.
        """
        if payload_id not in self.active_ids:
            return None

        file_path = SHM_DIR / f"netsentinel_decrypted_{payload_id}.enc"
        if not file_path.exists():
            return None

        try:
            with file_path.open("rb") as f:
                encrypted_data = f.read()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return decrypted_data.decode("utf-8")
        except Exception:
            return None

    def clear(self) -> None:
        """
        Deletes all RAM files and clears the keys.
        """
        for pid in list(self.active_ids):
            file_path = SHM_DIR / f"netsentinel_decrypted_{pid}.enc"
            if file_path.exists():
                with contextlib.suppress(Exception):
                    file_path.unlink()
        self.active_ids.clear()

        # Re-generate key to rotate it
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
