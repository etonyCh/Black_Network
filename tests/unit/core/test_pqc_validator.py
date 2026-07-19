import tempfile
from pathlib import Path

import pytest

from netsentinel.core.audit.pqc_validator import PQCValidator


def test_pqc_validator_loading_success():
    validator = PQCValidator()
    assert len(validator.ciphers_db) > 0
    assert validator.ciphers_db["mlkem768"] == "quantum_safe"


def test_pqc_validator_integrity_failure():
    # Create temporary reference database with tampered content
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_f:
        temp_f.write('{"ciphers": {}}')
        temp_path = temp_f.name

    try:
        # Load with tampered hash, expect ValueError
        with pytest.raises(ValueError, match="integrity check failed"):
            PQCValidator(temp_path)
    finally:
        Path(temp_path).unlink()


def test_evaluate_ciphers():
    validator = PQCValidator()

    # Empty list
    assert validator.evaluate_ciphers([]) == "VULNERABLE"

    # Only weak/vulnerable
    assert validator.evaluate_ciphers(["ssh-rsa", "3des-cbc"]) == "VULNERABLE"

    # Unrecognized is treated as vulnerable/untrusted
    assert validator.evaluate_ciphers(["unknown-cipher"]) == "VULNERABLE"

    # Hybrid (strong classical + weak) -> Vulnerable
    assert validator.evaluate_ciphers(["ssh-ed25519", "ssh-rsa"]) == "VULNERABLE"

    # Hybrid PQC + weak -> Vulnerable
    assert validator.evaluate_ciphers(["mlkem768x25519-sha256", "3des-cbc"]) == "VULNERABLE"

    # Pure strong classical
    assert (
        validator.evaluate_ciphers(["ssh-ed25519", "aes256-gcm@openssh.com"]) == "CLASSICAL_STRONG"
    )

    # Pure quantum safe
    assert validator.evaluate_ciphers(["mlkem768x25519-sha256"]) == "QUANTUM_SAFE"

    # Hybrid quantum safe + classical strong -> Quantum Safe
    assert validator.evaluate_ciphers(["ssh-ed25519", "mlkem768x25519-sha256"]) == "QUANTUM_SAFE"
