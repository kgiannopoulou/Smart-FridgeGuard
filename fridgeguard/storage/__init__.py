"""Centralized SQLite event storage (FR-7, NFR-2)."""

from fridgeguard.storage.store import EventStore, IngestResult, import_jsonl

__all__ = ["EventStore", "IngestResult", "import_jsonl"]
