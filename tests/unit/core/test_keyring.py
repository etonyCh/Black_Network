from unittest.mock import patch

import keyring

from netsentinel.core.secrets.keyring_store import KeyringStore


def test_keyring_store_fallback():
    # Force fallback mode to test storage in CI/test environments
    store = KeyringStore(use_fallback=True)

    assert store.get_secret("test_key") is None

    store.set_secret("test_key", "super_secret_value")
    assert store.get_secret("test_key") == "super_secret_value"

    # Try deleting
    assert store.delete_secret("test_key") is True
    assert store.get_secret("test_key") is None

    # Deleting non-existent should return False
    assert store.delete_secret("test_key") is False


def test_keyring_store_auto_detection():
    store = KeyringStore()
    # It should automatically detect headless env and set use_fallback
    assert isinstance(store.use_fallback, bool)


@patch("netsentinel.core.secrets.keyring_store.keyring")
def test_keyring_store_mocked_success(mock_keyring):
    # Set fallback to False
    store = KeyringStore(use_fallback=False)
    store.use_fallback = False  # force false

    # Test set
    store.set_secret("real_key", "real_val")
    mock_keyring.set_password.assert_called_with("netsentinel", "real_key", "real_val")

    # Test get
    mock_keyring.get_password.return_value = "real_val"
    assert store.get_secret("real_key") == "real_val"

    # Test delete
    assert store.delete_secret("real_key") is True
    mock_keyring.delete_password.assert_called_with("netsentinel", "real_key")


@patch("netsentinel.core.secrets.keyring_store.keyring")
def test_keyring_store_mocked_exceptions(mock_keyring):
    store = KeyringStore(use_fallback=False)
    store.use_fallback = False  # force false

    # Set password raises exception -> falls back
    mock_keyring.set_password.side_effect = Exception("keyring locked")
    store.set_secret("secret_key", "secret_val")
    assert store.use_fallback is True
    assert store.get_secret("secret_key") == "secret_val"

    # Get password raises exception -> falls back
    store.use_fallback = False
    mock_keyring.get_password.side_effect = Exception("failed lookup")
    assert store.get_secret("secret_key") == "secret_val"

    # Delete password raises PasswordDeleteError -> returns False
    store.use_fallback = False
    mock_keyring.delete_password.side_effect = keyring.errors.PasswordDeleteError("not found")
    assert store.delete_secret("missing_key") is False

    # Delete password raises generic exception
    mock_keyring.delete_password.side_effect = Exception("db error")
    store._fallback_store["some_key"] = "val"
    assert store.delete_secret("some_key") is True
