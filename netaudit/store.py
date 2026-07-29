"""Local versioned config storage."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from netaudit.models import BackupMeta


def _safe_name(name: str) -> str:
    return re.sub(r"[^\w.\-]+", "_", name)


class ConfigStore:
    """Stores configs under backups/<device>/<timestamp>.cfg with an index."""

    def __init__(self, root: str | Path = "backups") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.json"
        if not self.index_path.exists():
            self._write_index({})

    def _read_index(self) -> dict:
        return json.loads(self.index_path.read_text(encoding="utf-8"))

    def _write_index(self, data: dict) -> None:
        self.index_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @staticmethod
    def sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def save(
        self,
        device_name: str,
        config: str,
        source: str = "ssh",
        timestamp: str | None = None,
    ) -> BackupMeta:
        """Save a config snapshot. Skips write if identical to latest (same hash)."""
        ts = timestamp or BackupMeta.now_iso()
        device_dir = self.root / _safe_name(device_name)
        device_dir.mkdir(parents=True, exist_ok=True)

        digest = self.sha256(config)
        latest = self.latest(device_name)
        if latest and latest.sha256 == digest:
            return latest  # unchanged — reuse existing

        # Two snapshots inside the same second (a scheduled run and an
        # alert-triggered one, say) must not overwrite each other. The suffix is
        # appended so timestamps keep sorting oldest to newest as plain strings.
        base_ts = ts
        path = device_dir / f"{ts}.cfg"
        collision = 0
        while path.exists():
            collision += 1
            ts = f"{base_ts}{collision}"
            path = device_dir / f"{ts}.cfg"
        path.write_text(config, encoding="utf-8", newline="\n")

        meta = BackupMeta(
            device=device_name,
            timestamp=ts,
            path=str(path.as_posix()),
            sha256=digest,
            size_bytes=len(config.encode("utf-8")),
            source=source,
        )

        index = self._read_index()
        entries = index.setdefault(device_name, [])
        entries.append(
            {
                "timestamp": meta.timestamp,
                "path": meta.path,
                "sha256": meta.sha256,
                "size_bytes": meta.size_bytes,
                "source": meta.source,
            }
        )
        # Keep newest last; sort by timestamp
        entries.sort(key=lambda e: e["timestamp"])
        self._write_index(index)
        return meta

    def list_backups(self, device_name: str | None = None) -> list[BackupMeta]:
        index = self._read_index()
        result: list[BackupMeta] = []
        devices = [device_name] if device_name else sorted(index.keys())
        for name in devices:
            for entry in index.get(name, []):
                result.append(
                    BackupMeta(
                        device=name,
                        timestamp=entry["timestamp"],
                        path=entry["path"],
                        sha256=entry["sha256"],
                        size_bytes=entry["size_bytes"],
                        source=entry.get("source", "ssh"),
                    )
                )
        return result

    def latest(self, device_name: str) -> BackupMeta | None:
        backups = self.list_backups(device_name)
        return backups[-1] if backups else None

    def get(self, device_name: str, timestamp: str | None = None) -> tuple[BackupMeta, str]:
        """Load config text. If timestamp is None, use latest."""
        if timestamp:
            backups = [b for b in self.list_backups(device_name) if b.timestamp == timestamp]
            if not backups:
                raise FileNotFoundError(f"No backup {device_name} @ {timestamp}")
            meta = backups[0]
        else:
            meta = self.latest(device_name)
            if not meta:
                raise FileNotFoundError(f"No backups for {device_name}")
        text = Path(meta.path).read_text(encoding="utf-8")
        return meta, text

    def previous(self, device_name: str) -> BackupMeta | None:
        backups = self.list_backups(device_name)
        if len(backups) < 2:
            return None
        return backups[-2]

    def import_file(self, device_name: str, path: str | Path, source: str = "file") -> BackupMeta:
        text = Path(path).read_text(encoding="utf-8")
        return self.save(device_name, text, source=source)
