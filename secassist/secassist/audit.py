"""Lückenloses Audit-Log (JSON Lines) – wichtig als Nachweis gegenüber Kunden."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, directory: str, session_id: str):
        os.makedirs(directory, exist_ok=True)
        self.path = os.path.join(directory, f"{session_id}.jsonl")
        self._lock = threading.Lock()

    def write(self, event: str, **data) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **data}
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
