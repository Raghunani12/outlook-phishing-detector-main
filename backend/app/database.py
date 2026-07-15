"""
MongoDB Atlas connection.

Two collections by design:
  - scans           -> small documents, queried constantly by the dashboard
                        (lists, metrics, aggregations). Never holds full raw
                        payloads so these queries stay fast.
  - raw_scan_data    -> heavy documents (raw headers, raw email body, full
                        VirusTotal JSON, full DNS answers, exact Gemini
                        prompt/response). Only fetched when an admin clicks
                        "View Source" on a specific scan.

Both documents for a given scan share the same _id (as a string) so they
can be joined with a single extra lookup, no separate foreign key scheme
needed.
"""

import os
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


async def connect_to_mongo() -> None:
    global _client, _db
    uri = os.getenv("MONGODB_URI")
    db_name = os.getenv("MONGODB_DB_NAME", "phish_raksha")
    if not uri:
        raise RuntimeError("MONGODB_URI is not set. Copy .env.example to .env and fill it in.")

    _client = AsyncIOMotorClient(uri)
    _db = _client[db_name]

    # Fail fast on startup if Atlas isn't reachable, instead of failing
    # silently on the first request.
    await _client.admin.command("ping")

    # Indexes that make the dashboard's actual queries fast. Safe to run
    # every startup -- create_index is a no-op if the index already exists.
    await scans_collection().create_index("scanned_at")
    await scans_collection().create_index("scanned_by")
    await scans_collection().create_index("verdict")
    await scans_collection().create_index("sender_domain")


async def close_mongo_connection() -> None:
    if _client:
        _client.close()


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("Database not initialized. Did startup run connect_to_mongo()?")
    return _db


def scans_collection() -> AsyncIOMotorCollection:
    return get_db()["scans"]


def raw_collection() -> AsyncIOMotorCollection:
    return get_db()["raw_scan_data"]
