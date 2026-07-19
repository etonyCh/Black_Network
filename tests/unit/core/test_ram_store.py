from pathlib import Path

from netsentinel.core.secrets.ram_store import RamStore


def test_ram_store_lifecycle():
    store = RamStore()

    # 1. Storing data
    data = "Secret decrypted payload content"
    pid = store.store(data)
    assert isinstance(pid, str)
    assert len(pid) > 0

    # Verify file is created in /dev/shm
    file_path = Path(f"/dev/shm/netsentinel_decrypted_{pid}.enc")
    assert file_path.exists()

    # Verify content in file is encrypted (raw text not in file)
    with file_path.open("rb") as f:
        encrypted_bytes = f.read()
    assert data.encode("utf-8") not in encrypted_bytes

    # 2. Retrieving data
    retrieved = store.retrieve(pid)
    assert retrieved == data

    # 3. Clearing store
    store.clear()
    assert not file_path.exists()
    assert store.retrieve(pid) is None
    assert len(store.active_ids) == 0
