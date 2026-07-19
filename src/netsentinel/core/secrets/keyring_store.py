import os

import keyring
from keyring.errors import PasswordDeleteError

APP_NAME = "netsentinel"


class KeyringStore:
    def __init__(self, use_fallback: bool = False):
        self.use_fallback = use_fallback or self._is_headless()
        self._fallback_store = {}  # type: dict[str, str]

    def _is_headless(self) -> bool:
        # DBUS_SESSION_BUS_ADDRESS is required for GNOME Keyring communication.
        # If it is missing (like in headless CI), we should auto-fallback to mock storage.
        return "DBUS_SESSION_BUS_ADDRESS" not in os.environ

    def set_secret(self, key_name: str, secret_value: str) -> None:
        """
        Stores a secret securely under the NetSentinel namespace.
        """
        if self.use_fallback:
            self._fallback_store[key_name] = secret_value
            return

        try:
            keyring.set_password(APP_NAME, key_name, secret_value)
        except Exception:
            # Fallback if Keyring service is locked or unavailable
            self.use_fallback = True
            self._fallback_store[key_name] = secret_value

    def get_secret(self, key_name: str) -> str | None:
        """
        Retrieves a stored secret. Returns None if it does not exist.
        """
        if self.use_fallback:
            return self._fallback_store.get(key_name)

        try:
            return keyring.get_password(APP_NAME, key_name)
        except Exception:
            # Fallback lookup
            return self._fallback_store.get(key_name)

    def delete_secret(self, key_name: str) -> bool:
        """
        Deletes a secret from the store. Returns True if deleted, False otherwise.
        """
        if self.use_fallback:
            if key_name in self._fallback_store:
                del self._fallback_store[key_name]
                return True
            return False

        try:
            keyring.delete_password(APP_NAME, key_name)
            return True
        except PasswordDeleteError:
            return False
        except Exception:
            if key_name in self._fallback_store:
                del self._fallback_store[key_name]
                return True
            return False
