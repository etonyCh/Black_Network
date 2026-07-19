import hashlib
import json
from pathlib import Path

DEFAULT_REFERENCE_PATH = (
    Path(__file__).parent.parent.parent.parent.parent / "data" / "pqc_nist_reference.json"
)
EXPECTED_HASH = "f070bd913871ff7eaacd2706d5c6e704ffc410d27c43dc7a1a5c4f440c3339db"


class PQCValidator:
    def __init__(self, reference_path: Path | str = DEFAULT_REFERENCE_PATH):
        self.reference_path = Path(reference_path)
        self.ciphers_db = {}  # type: dict[str, str]
        self._load_reference()

    def _calculate_file_hash(self) -> str:
        hasher = hashlib.sha256()
        with self.reference_path.open("rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _load_reference(self) -> None:
        if not self.reference_path.exists():
            raise FileNotFoundError(f"NIST PQC reference file not found at: {self.reference_path}")

        # Integrity Check
        actual_hash = self._calculate_file_hash()
        if actual_hash != EXPECTED_HASH:
            raise ValueError(
                f"PQC reference file integrity check failed! "
                f"Expected hash: {EXPECTED_HASH}, got: {actual_hash}"
            )

        with self.reference_path.open() as f:
            data = json.load(f)
            self.ciphers_db = data.get("ciphers", {})

    def evaluate_ciphers(self, ciphers: list[str]) -> str:
        """
        Evaluates a list of ciphers and returns the general PQC compliance status:
        - "QUANTUM_SAFE": At least one PQC algorithm supported.
        - "CLASSICAL_STRONG": All ciphers are classical strong.
        - "VULNERABLE": Any cipher matches "vulnerable" or is unrecognized.
        """
        if not ciphers:
            return "VULNERABLE"

        has_pqc = False
        has_vulnerable = False

        for cipher in ciphers:
            cipher = cipher.strip()
            status = self.ciphers_db.get(cipher, "vulnerable")
            if status == "quantum_safe":
                has_pqc = True
            elif status == "vulnerable":
                has_vulnerable = True

        if has_vulnerable:
            return "VULNERABLE"
        if has_pqc:
            return "QUANTUM_SAFE"
        return "CLASSICAL_STRONG"
