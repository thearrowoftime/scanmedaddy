"""Config store behaviour: hashing, dedup, ordering."""

from __future__ import annotations

from pathlib import Path

from netaudit.store import ConfigStore

CONFIG_A = "hostname a\nsnmp-server community public RO\n"
CONFIG_B = "hostname a\nsnmp-server community s3cr3t RO\n"


def test_identical_config_is_not_stored_twice(tmp_path: Path):
    store = ConfigStore(tmp_path / "backups")
    first = store.save("sw-01", CONFIG_A)
    second = store.save("sw-01", CONFIG_A)

    assert second.timestamp == first.timestamp
    assert len(store.list_backups("sw-01")) == 1


def test_two_snapshots_in_the_same_second_are_both_kept(tmp_path: Path):
    """A scheduled run and an alert-triggered run can collide on the timestamp."""
    store = ConfigStore(tmp_path / "backups")
    stamp = "20260729T191203Z"

    first = store.save("sw-01", CONFIG_A, timestamp=stamp)
    second = store.save("sw-01", CONFIG_B, timestamp=stamp)

    assert first.timestamp != second.timestamp
    assert Path(first.path).exists()
    assert Path(second.path).exists()
    assert Path(first.path).read_text(encoding="utf-8") == CONFIG_A
    assert Path(second.path).read_text(encoding="utf-8") == CONFIG_B

    backups = store.list_backups("sw-01")
    assert len(backups) == 2
    # newest must still sort last, so latest()/previous()/diff stay correct
    assert store.latest("sw-01").sha256 == second.sha256
    assert store.previous("sw-01").sha256 == first.sha256


def test_collision_suffix_keeps_chronological_order(tmp_path: Path):
    store = ConfigStore(tmp_path / "backups")
    store.save("sw-01", CONFIG_A, timestamp="20260729T191203Z")
    store.save("sw-01", CONFIG_B, timestamp="20260729T191203Z")
    store.save("sw-01", CONFIG_A + "! later\n", timestamp="20260729T191204Z")

    timestamps = [b.timestamp for b in store.list_backups("sw-01")]
    assert timestamps == sorted(timestamps)
    assert timestamps[-1] == "20260729T191204Z"


def test_get_returns_the_requested_snapshot(tmp_path: Path):
    store = ConfigStore(tmp_path / "backups")
    store.save("sw-01", CONFIG_A, timestamp="20260729T191203Z")
    store.save("sw-01", CONFIG_B, timestamp="20260729T191300Z")

    meta, text = store.get("sw-01", "20260729T191203Z")
    assert text == CONFIG_A
    assert meta.size_bytes == len(CONFIG_A.encode("utf-8"))

    _latest_meta, latest_text = store.get("sw-01")
    assert latest_text == CONFIG_B


def test_import_file_records_source(tmp_path: Path):
    store = ConfigStore(tmp_path / "backups")
    source_file = tmp_path / "device.cfg"
    source_file.write_text(CONFIG_A, encoding="utf-8")

    meta = store.import_file("sw-01", source_file)
    assert meta.source == "file"
    assert meta.sha256 == ConfigStore.sha256(CONFIG_A)
